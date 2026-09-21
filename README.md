# IDS
ml

{
    "session_id": "S001",
    "timestamp": {
        "start": "2026-09-04T00:01:15.125Z",
        "end": "2026-09-04T00:01:16.348Z",
        "duration": 1.223
    },

    "network": {
        "src_ip": "192.168.10.5",
        "dst_ip": "192.168.10.20",
        "src_port": 51500,
        "dst_port": 80,
        "protocol": "TCP"
    },

    "flag": {
        "syn": 1,
        "syn_ack": 1,
        "ack": 1,
        "fin": 1,
        "rst": 0,
        "psh": 8,
        "ack_count": 18
    },

    "packets": {
        "total": 28,

        "forward": {
            "count": 18,
            "bytes": 5200
        },

        "backward": {
            "count": 10,
            "bytes": 3100
        }
    },

    "flow": {
        "total_bytes": 8300,
        "bytes_per_second": 6786.59,
        "packets_per_second": 22.89,

        "packet_length": {
            "min": 40,
            "max": 1460,
            "mean": 296.43,
            "std": 182.51
        },

        "iat": {
            "mean": 0.045,
            "std": 0.031,
            "min": 0.002,
            "max": 0.210
        }
    },

    "http": {
        "is_http": true,

        "transactions": 
            {
                "requests": [
                    {
                    "method": "POST",
                    "host": "192.168.10.20",
                    "uri": "/login",
                    "version": "HTTP/1.1",
                    "body": "username=admin&password=123",
                    "payload": {
                        "length": 35,
                        "parameter_count": 2,
                        "special_character_count": 0,
                        "encoded_character_count": 0
                    }
                },
                    {
                    "method": "POST",
                    "host": "192.168.10.20",
                    "uri": "/login",
                    "version": "HTTP/1.1",
                    "body": "username=admin&password=123",
                    "payload": {
                        "length": 35,
                        "parameter_count": 2,
                        "special_character_count": 0,
                        "encoded_character_count": 0
                    }
                }
            ],
            

                "responses" : [
                    {
                    "status_code": 401,
                    "content_length": 25
                }
            ]
        }
        
    },


    "connection": {
        "request_count": 2,
        "response_count": 1,
        "status_code": 200
    }
}

{
  "alert_id": "ALT-000001",
  "timestamp": "time.time()",           

  "attack_type": "Brute Force",
  "severity": "HIGH",

  "source_ip": "192.168.1.10",
  "destination_ip": "192.168.1.20",

  "detection_method": "Behavior",
  "rule_id": "BF-001",
  "confidence": 0.94,

  "evidence": {
    "request_count": 120,
    "time_window": 60,
    "failed_login_count": 118
  },

  "description": "Phát hiện số lượng đăng nhập thất bại bất thường trong 60 giây.",

  "action": "ALERT"
}
