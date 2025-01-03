import base64
import json
import subprocess

## https://iden3-circuits-bucket.s3.eu-west-1.amazonaws.com/feature/trusted-setup-v1.0.0.zip

def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True
        )

        return result.stdout, result.stderr, result.returncode

    except subprocess.CalledProcessError as e:
        return "", e.stderr, e.returncode


vp_json_file = "vp.json"

credential_prefix = 'credential_'
jwz_prefix = 'jwz_'


def run():

    with open(vp_json_file, "r", encoding="utf-8") as file:
        data = json.load(file)

    token = data["token"]

    authResponse = data['authResponse']
    holderDID = authResponse['from']
    issuerDID = authResponse['to']
    print("Holder DID:", holderDID)
    print("Issuer DID:", issuerDID)

    scope = authResponse['body']['scope'][0]

    for name in ["proof", "pub_signals"]:
        with open(f"{credential_prefix}{name}.json", "w", encoding="utf-8") as file:
            json.dump(scope[name], file, ensure_ascii=False, indent=4)

    verfication_key_file = f"{scope['circuitId']}/verification_key.json"
    command = f"snarkjs groth16 verify {verfication_key_file} {credential_prefix}pub_signals.json {credential_prefix}proof.json"
    stdout, stderr, returncode = run_command(command)
    if len(stdout) > 0:
        print(stdout)
    if len(stderr) > 0:
        print(stderr)
    print("VP Verification:", "Success" if returncode == 0 else "Failed")

    jwz_array = token.split(".")

    assert (len(jwz_array) == 3)

    encoded_str = jwz_array[0] + '=' * (4 - len(jwz_array[0]) % 4)
    decoded_bytes = base64.b64decode(encoded_str).decode("utf-8")
    header_data = json.loads(decoded_bytes)
    pretty_header = json.dumps(header_data,
                               indent=4, ensure_ascii=False)
    print("")
    print("JWZ Header")
    print(pretty_header)

    jwz_circuit_id = header_data['circuitId']

    encoded_str = jwz_array[1] + '=' * (4 - len(jwz_array[1]) % 4)
    decoded_bytes = base64.b64decode(encoded_str).decode("utf-8")
    payload = json.loads(decoded_bytes)
    print("")
    print("JWZ Payload:", "Matched" if payload == authResponse else "Failed")

    encoded_str = jwz_array[2] + '=' * (4 - len(jwz_array[2]) % 4)
    decoded_bytes = base64.b64decode(encoded_str).decode("utf-8")
    authv2_data = json.loads(decoded_bytes)
    print("")
    for name in ["proof", "pub_signals"]:
        with open(f"{jwz_prefix}{name}.json", "w", encoding="utf-8") as file:
            json.dump(authv2_data[name], file, ensure_ascii=False, indent=4)

    verfication_key_file = f"{jwz_circuit_id}/verification_key.json"
    command = f"snarkjs groth16 verify {verfication_key_file} {jwz_prefix}pub_signals.json {jwz_prefix}proof.json"
    stdout, stderr, returncode = run_command(command)
    if len(stdout) > 0:
        print(stdout)
    if len(stderr) > 0:
        print(stderr)
    print("JWZ Verification:", "Success" if returncode == 0 else "Failed")


if __name__ == "__main__":
    run()
