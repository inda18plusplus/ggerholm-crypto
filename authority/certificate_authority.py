from network.socket_protocol import generate_keys


# TODO: Remove / fix

class CertificateAuthority(object):
    certificates = {}

    def __init__(self):
        self.signing_key, self.verify_key_hex = generate_keys()

    def register(self, identifier):
        pass

    def get_certificate(self, cert_id):
        if cert_id not in self.certificates.keys():
            return None
        return self._sign_certificate(cert_id)

    def _sign_certificate(self, cert_id):
        signed = self.signing_key.sign(self.certificates[cert_id])
        return signed
