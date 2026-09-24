"""
Ghep lai cac goi TCP thuoc cung 1 chieu (forward/backward) cua 1 session
thanh tung HTTP message HOAN CHINH, truoc khi dua cho
packet_parser.extract_http() phan tich.
"""

import re

_HEADER_END = b"\r\n\r\n"
_CONTENT_LENGTH_RE = re.compile(r"(?im)^content-length\s*:\s*(\d+)\s*$")


class TCPStreamReassembler:

    # Gioi han buffer moi chieu, tranh phinh bo nho neu goi tin lien tuc
    # khong bao gio tao thanh 1 HTTP message hop le (VD flood rac).
    MAX_BUFFER = 5 * 1024 * 1024  # 5MB

    def __init__(self):
        self._buffers = {"forward": b"", "backward": b""}

    def feed(self, direction, payload):
        """
        Them du lieu TCP moi vao buffer cua 1 chieu. Tra ve list cac khoi
        byte da la 1 HTTP message HOAN CHINH (co the > 1 neu server/client
        gui nhieu request/response lien tiep tren cung 1 ket noi keep-alive).
        Phan con thieu (message chua nhan het) van duoc giu lai trong buffer
        cho lan feed() ke tiep.
        """
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

            content_length = self._extract_content_length(header_section)

            total_length = body_start + content_length

            if len(buf) < total_length:
                break  # Header da xong nhung body chua den du, cho them

            message = buf[:total_length]
            complete_messages.append(message)

            buf = buf[total_length:]

        self._buffers[direction] = buf

        return complete_messages

    @staticmethod
    def _extract_content_length(header_section):
        try:
            text = header_section.decode("utf-8", errors="ignore")
        except Exception:
            return 0

        match = _CONTENT_LENGTH_RE.search(text)
        if match:
            return int(match.group(1))

        return 0
