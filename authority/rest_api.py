from flask import Flask

from authority.certificate_authority import CertificateAuthority

app = Flask(__name__)


# TODO: Remove / fix

@app.route('/certificate?identifier=<string:identifier>', methods=['GET'])
def get_certificate(identifier):
    certificate = ca.get_certificate(identifier)
    if not certificate:
        return None, 404
    return certificate, 200


if __name__ == '__main__':
    ca = CertificateAuthority()
    app.run('127.0.0.1', 7124, debug=True)
