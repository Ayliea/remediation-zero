# Copyright 2026 Daviyon Daniels
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Input bound shared by every adapter."""
from tools.model_transport import MAX_INPUT_BYTES


def check_input(system, user):
    if len((system + user).encode()) > MAX_INPUT_BYTES:
        raise ValueError(f'input exceeds {MAX_INPUT_BYTES} bytes')
