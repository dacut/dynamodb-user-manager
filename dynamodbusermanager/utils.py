#!/usr/bin/env python3
from functools import lru_cache
from os import environ
import requests
from requests.exceptions import ConnectTimeout

AZ_METADATA_URL = (
    "http://169.254.169.254/2018-09-24/meta-data/placement/"
    "availability-zone")
METADATA_TIMEOUT = 0.1

@lru_cache()
def get_region():
    """
    get_region() -> str
    Returns the name of the region to use.

    This returns the first result found from:
      * The environment variable AWS_REGION
      * The environment variable AWS_DEFAULT_REGION
      * Instance availability zone
      * us-gov-west-1
    """
    region = environ.get("AWS_REGION")
    if not region:
        region = environ.get("AWS_DEFAULT_REGION")
    if not region:
        try:
            az = requests.get(AZ_METADATA_URL, timeout=METADATA_TIMEOUT).text
        except ConnectTimeout:
            pass
        region = az[:-1]
    if not region:
        region = "us-gov-west-1"
    
    return region
