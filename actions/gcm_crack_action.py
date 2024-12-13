from typing import Dict, Any

from gcm_crack.gcm_types import json_to_gcm_message, json_forgery_to_gcm_message
from gcm_crack.gcm_crack import gcm_crack


def gcm_crack_action(arguments: Dict[str, Any]) -> Dict[str, Any]:
    # nonce = B64(arguments["nonce"]).block
    m1 = json_to_gcm_message(arguments["m1"])
    m2 = json_to_gcm_message(arguments["m2"])
    m3 = json_to_gcm_message(arguments["m3"])

    forgery = json_forgery_to_gcm_message(arguments["forgery"])

    tag, H, mask = gcm_crack(m1, m2, m3, forgery)

    return {"tag": tag.to_b64_gcm(), "H": H.to_b64_gcm(), "mask": mask.to_b64_gcm()}
