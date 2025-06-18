# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Config classes which is a data storage class for parser
generation configuration information.
"""

import os
import customtypes
import json
import base64

class Config:
    """
    This class stores data related to the high level configuration of the
    parser to be generated.

    Settable class variables:
        protocol: The name of the protocol.
        scopes: An array of strings with the scope names used within the
            parser. These are used as subfolder names for additional parser
            processing.
        entryPoint: The Object name in "scope.ObjectName" notation
            (e.g., "general.Message") used to start processing packets.
        usesTCP: Whether or not this protocol uses TCP.
        usesUDP: Whether or not this protocol uses UDP.
        usesLayer2: Whether or not this protocol uses Ethernet instead of TCP
            or UDP.
        ethernetProtocolNumber: Ethernet Header Protocol Number value
            (used when usesLayer2 is set to True).
        ports: Array of dictionaries with two keys: "protocol" and "port".
            Valid values for "protocol" entry: "tcp" and "udp".
        customFieldTypes: Set of tuples with the key being the
            user-defined custom type name and the tuple consisting of:
            the user-defined custom type name, the conversion function name
            used to convert the custom type, and the return type of the
            conversion function.
        signatureFile: Base-64 encoded signature file.
        conversionFile: Base-64 encoded conversion code file.
        gitignoreFile: Base-64 encoded .gitignore file.
        shortDescription: A short description of the protocol.
        longDescription: A longer description of the protocol.
        """
    def __init__(self):
        """
        Basic Initialization Function
        """
        self.protocol = ""
        self.scopes = []
        self.entryPoint = ""
        self.usesTCP = False
        self.usesUDP = False
        self.usesLayer2 = False
        self.ethernetProtocolNumber = 0
        self.ports = []
        self.customFieldTypes = {}
        self.signatureFile = None
        self.conversionFile = None
        self.gitignoreFile = None
        self.shortDescription = ""
        self.longDescription = ""

def loadConfig(configFilePath):
    """
    Loads a parser configuration from a Parsnip-formatted Configuration JSON
    file.

    Args:
        configFilePath (str): Path to the configuration file.

    Returns:
        (Bool, Config): A tuple with the first value being if the file was
            successfully loaded and parsed and the second value being the
            Config object loaded with the parsed information.
    """
    config = Config()
    if not (os.path.isfile(configFilePath)):
        return (False, config)

    with open(configFilePath, "r+") as file:
        configObject = json.load(file)

    config.protocol = configObject["Protocol"]
    config.scopes = configObject["Scopes"]
    config.entryPoint = configObject["EntryPoint"]

    if "usesTCP" in configObject and configObject["usesTCP"] == True:
        config.usesTCP = True

    if "usesUDP" in configObject and configObject["usesUDP"] == True:
        config.usesUDP = True

    if "usesLayer2" in configObject and configObject["usesLayer2"] == True:
        config.usesLayer2 = True

    if "ethernetProtocolNumber" in configObject:
        config.ethernetProtocolNumber = configObject["ethernetProtocolNumber"]

    if "Ports" in configObject:
        config.ports = configObject["Ports"]

    if "CustomFieldTypes" in configObject:
        for item in configObject["CustomFieldTypes"]:
            config.customFieldTypes[item.get("name")] = customtypes.CustomType(item.get("name"), item.get("interpretingFunction"), item.get("returnType"))

    if "signatureFile" in configObject and "" != configObject.get("signatureFile"):
        config.signatureFile = base64.b64decode(configObject.get("signatureFile")).decode()

    if "conversionFile" in configObject and "" != configObject.get("conversionFile"):
        config.conversionFile = base64.b64decode(configObject.get("conversionFile")).decode()

    if "gitignoreFile" in configObject and "" != configObject.get("gitignoreFile"):
        config.gitignoreFile = base64.b64decode(configObject.get("gitignoreFile")).decode()

    if "protocolShortDescription" in configObject and "" != configObject.get("protocolShortDescription"):
        config.shortDescription = configObject["protocolShortDescription"]

    if "protocolLongDescription" in configObject and "" != configObject.get("protocolLongDescription"):
        config.longDescription = configObject["protocolLongDescription"]

    return (True, config)
