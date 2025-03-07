import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes

# Decode the private key from base64
private_key_b64 = "LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBcVhSV3oydGVTNlY3TUFnQU1nOWNveWg5cHdnZVFjZXRCM0JLeFRQbGJHVlRGb0dpClBFWktEeWcxVG1DWGQ2MkhJdzVpUFgzMG01dmE4S3VnMGVLWXJFNFQ5QnduS2tXbzZaQTBTT1VHTEt2WG1nOHYKRXFiakNSWEprdnF3YjFjeUJaMVlrTXk4cFpiRVh4aWFGVGdBY3BPU2dlUklOTTI2ZVBKaC9YUmZ6eXBPR1VKTgprWUtISEdBS2NFWVk1S3hVQkttTkZuQmRQTGNzNXM5RjlIRHZIZFFxUnNsNnJ3MWRocFIxaHBES3ZVOVJjd1BmCklhekd0UVJhN0lEUzNZejlSRjYrbkV0QVBIY3RoR1VIODMrdVJiUFJ5VEdCSXBUU0xDdlo5WWhsZzF4M3I3V24KVGNwZ29yRmNsRDYwamJDZDhGbnZGZkFHL1loMHQ2R3VUZFR5cVFJREFRQUJBb0lCQUFUNXBhRFh1Z0F3NlhIVgpaNks3Uzd0OThWa3BtN0I2WmRkTmtlSENBODdsRjFycnBIRkRtUXkzMy85MG00M2RKT3RxWjl6K3FUaTJZSkpuClg1bmtuc1NVVXZGUnNFbGFtK1VtVERxd1ZXTG90Vjc3Rk0vbDRYZy9VUU5GT1UvbzQwN3NqenRLZE9iTVlKTkYKaHM5RkFuMEZYZGI5ZGxkQ2k3ZmRyMGlBbGJMZ2lBaW12RW9lbHRRSFZnR0hUMEhDazB4ZGVwaEZsbFMxeDhGegpZOEd4RTBtS1B3ZUFyamxsWjduVWwwUENxQURLWWZFZ29OK2dxWTJWQ2Z0V1VBcUZNeWlxOFZvRHBPKzQvK09iClFHWXdjZWZWR2RXQit1NElwTlBhR1o1TUs4M2V4YlpyeTJNMDlsNmNJeGlYYVk1bituTkZuOC9jS1hmTmxzQnUKa2pwa0VtY0NnWUVBMUI4azQ3M0o5ak9lWlJweVZGS0IvZDRERkcrZUt4VTkrYTBhVDFZRkptTzJkUlNZSlZsbQpnSnpwWXpJcXZ3V1R5VlpGMDZyakRFMkVLZlIvUHczWkM4dW44WUZoUkMrOEhZQXRVM3JTemZBRnNaYTJOYTZpCkRjMzRCWkVWU0s3TThRam9qMVBONzVIanN3ckV2OXF2TTV1QjE0dk9FMlFPV2RlYXJ6dmFVa3NDZ1lFQXpJSEQKTERQTG1TL0h5SkRWdWIyZ2MwQlYyZ0hHOWsralc0MHgrYndMdW9yYnpCR2Mrd2dNSTFRYks5UFgvRkJUNTBLUAo0TSt6alZ1OGVXSTVyQURhWG9xWVZOYXBwRk1UVXFLekNWeVorS3JJbEZwVXZnWlBTNzNOL09zSHRiekhvenI5ClhyWXltbEp3RlJLN28xZ3RBYTVES05aa2tES2FqNElUdWFYdDFsc0NnWUJTU1M2WFJoVmxjNHE3YjdId01mMkoKVEtsbk1SRnJaeGNlbHQ4QTdiNmJzTXlqeUhSbzhMQkpyaFQvVFFPMkRHVFRFcXVOdTluTitQZ1BDbkNlTmpILwpXR1p5MGh5NFJjZzByWGRuemRxZTFzQnVycWRLVmM4NWlhL3dBT0wveWdkb2JXdEJ4bUc1MEo5QzRpZUd3VDk3CnhwUnMyQ2Y5NzY5OWZKemQ0MXNDMXdLQmdBT3FvK3dyOVkrR2lzZHV5Vll1THkxQnp3ZzhsZXVlbStndFRPTVUKV3dWNkxkeW55Qys4QWpPejgxVEMxSkdDZ3k2WFErc2M3alF2bTk1MVEyRnhGbmt4ZE8rNGRZd3JyU0lESnNDWgpOMjE4Nm1HMmlPUnJTb3FxR1lKYVdHWUt2MjJPeGpJbmhCcStOYUk3RnNBaitaS1pKRDBjTXV0ZTdPUjd5WXkvCmk5Y1hBb0dCQUxzRTFxeVVJb0h6TG9wNStvQkVidGRiRU5USjBwVW1kTmhDUkhYN2tDaHlDMXMxZVBoOXJFakMKMzAzdlBlZ2NBN2ZSZkM2YXQvR2x2b3FSUWpackI2b3V5MEtWdDlSanlmMXFjWUVhZkphMnVWdnVGM252c3dhdApQRVFRZkhNMEpqQWZHU3ZGRE1ab1lUTCtuaCtKazFVQnFyQmNLYnQxSDYwQ1BKNWs2dWluCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg=="
private_key_pem = base64.b64decode(private_key_b64).decode()

# Message to encrypt (sign)
message = b"s0m3r4nd0mt3xt"

def sign_message(private_key_pem, message):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()