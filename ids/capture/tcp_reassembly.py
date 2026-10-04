"""
Ghep lai cac goi TCP thuoc cung 1 chieu (forward/backward) cua 1 session
thanh tung HTTP message HOAN CHINH, truoc khi dua cho
packet_parser.extract_http() phan tich.
"""

import re

_HEADER_END = b"\r\n\r\n"
_CONTENT_LENGTH_RE = re.compile(r"(?im)^content-length\s*:\s*(\d+)\s*$")
_TRANSFER_ENCODING_RE = re.compile(r"(?im)^transfer-encoding\s*:\s*([^\r\n]+)")
_STATUS_RE = re.compile(rb"^HTTP/\d(?:\.\d)?\s+(\d{3})")


class TCPStreamReassembler:
    """Reorder TCP payload per direction and extract complete HTTP messages."""

    # Gioi han buffer moi chieu, tranh phinh bo nho neu goi tin lien tuc
    # khong bao gio tao thanh 1 HTTP message hop le (VD flood rac).
    MAX_BUFFER = 5 * 1024 * 1024  # 5MB

    def __init__(self):
        self._buffers = {"forward": b"", "backward": b""}
        self._next_seq = {"forward": None, "backward": None}
        self._pending = {"forward": {}, "backward": {}}

    def feed(self, direction, payload, sequence=None):
        """Add a payload segment and return every newly complete HTTP message."""
        """
        Them du lieu TCP moi vao buffer cua 1 chieu. Tra ve list cac khoi
        byte da la 1 HTTP message HOAN CHINH (co the > 1 neu server/client
        gui nhieu request/response lien tiep tren cung 1 ket noi keep-alive).
        Phan con thieu (message chua nhan het) van duoc giu lai trong buffer
        cho lan feed() ke tiep.
        """
        if not payload:
            return []

        payload = self._order_payload(direction, payload, sequence)
        if not payload:
            return []

        buf = self._buffers.get(direction, b"") + payload

        if len(buf) > self.MAX_BUFFER:
            # Khong the xac dinh duoc ranh gioi message -> xoa buffer,
            # tranh tran bo nho. Chap nhan mat du lieu trong truong hop hiem
            # nay de doi lay an toan bo nho.
            self._buffers[direction] = b""
            return []

        complete_messages = []

        while True:
            header_end = buf.find(_HEADER_END)
            if header_end == -1:
                break  # Chua du header, cho them du lieu

            header_section = buf[:header_end]
            body_start = header_end + len(_HEADER_END)

            total_length = self._message_length(header_section, body_start, buf)
            if total_length is None:
                break  # response close-delimited: only FIN marks its end

            if len(buf) < total_length:
                break  # Header da xong nhung body chua den du, cho them

            message = buf[:total_length]
            complete_messages.append(message)

            buf = buf[total_length:]

        self._buffers[direction] = buf

        return complete_messages

    def _order_payload(self, direction, payload, sequence):
        """Reorder TCP segments and discard retransmitted/overlapping bytes."""
        if sequence is None:
            return payload
        sequence &= 0xffffffff
        expected = self._next_seq[direction]
        if expected is None:
            self._next_seq[direction] = (sequence + len(payload)) & 0xffffffff
            return payload

        distance = (sequence - expected) & 0xffffffff
        if distance == 0:
            ready = bytearray(payload)
            expected = (expected + len(payload)) & 0xffffffff
            pending = self._pending[direction]
            while expected in pending:
                segment = pending.pop(expected)
                ready.extend(segment)
                expected = (expected + len(segment)) & 0xffffffff
            self._next_seq[direction] = expected
            return bytes(ready)

        if distance < 0x80000000:
            # A future segment; cap queued data against malformed gaps/floods.
            pending = self._pending[direction]
            if len(pending) < 128 and sum(map(len, pending.values())) + len(payload) <= self.MAX_BUFFER:
                pending.setdefault(sequence, payload)
            return b""

        overlap = (expected - sequence) & 0xffffffff
        if overlap >= len(payload):
            return b""  # complete retransmission
        payload = payload[overlap:]
        self._next_seq[direction] = (expected + len(payload)) & 0xffffffff
        return payload

    def flush(self, direction):
        """Return residual bytes on FIN (notably close-delimited responses)."""
        data = self._buffers.get(direction, b"")
        self._buffers[direction] = b""
        return [data] if data else []

    @classmethod
    def _message_length(cls, header_section, body_start, buf):
        """Return framed message length, or None for a FIN-delimited response."""
        content_length = cls._extract_content_length(header_section)
        text = header_section.decode("iso-8859-1", errors="replace")
        transfer = _TRANSFER_ENCODING_RE.search(text)
        if transfer and "chunked" in transfer.group(1).lower():
            end = cls._chunked_end(buf, body_start)
            return end
        if content_length is not None:
            return body_start + content_length

        status = _STATUS_RE.match(header_section)
        if status:
            code = int(status.group(1))
            if 100 <= code < 200 or code in (204, 304):
                return body_start
            return None  # close-delimited response
        return body_start  # ordinary request without a body

    @staticmethod
    def _chunked_end(buf, body_start):
        pos = body_start
        while True:
            line_end = buf.find(b"\r\n", pos)
            if line_end < 0:
                return None
            size_text = buf[pos:line_end].split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                return None
            pos = line_end + 2
            if size == 0:
                trailer_end = buf.find(b"\r\n\r\n", pos)
                if trailer_end >= 0:
                    return trailer_end + 4
                if buf[pos:pos + 2] == b"\r\n":
                    return pos + 2
                return None
            pos += size
            if len(buf) < pos + 2:
                return None
            if buf[pos:pos + 2] != b"\r\n":
                return None
            pos += 2

    @staticmethod
    def _extract_content_length(header_section):
        try:
            text = header_section.decode("utf-8", errors="ignore")
        except Exception:
            return 0

        match = _CONTENT_LENGTH_RE.search(text)
        if match:
            return int(match.group(1))

        return None
