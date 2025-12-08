# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the main high level functions for Parsnip.
"""

import argparse

import utils
import json_processing as processing
import graphing

import generation_utils
import config

def _updateUtilValues(configuration):
    """
    Updates the global variables available in the Utils module.

    Args:
        configuration (Config): parser configuration information.
    """
    utils.PROTOCOL_NAME = configuration.protocol
    utils.USES_LAYER_2 = configuration.usesLayer2
    utils.customFieldTypes = configuration.customFieldTypes

def _parseArgs():
    """
    Parses the command line arguments for the tool and returns the input and
    output directories to use. Upon parsing error or "-h" argument found, it
    displays the help menu and exits the program.

    Returns:
        (str, str): a tuple with the following values:
            1. the input directory path parsed from the command line arguments.
            2. the output directory path parsed from the command line arguments.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("inputRootDirectory", type=str, help="Path to folder with '{0}' folder".format(utils.DEFAULT_SCOPE))
    parser.add_argument("outputRootDirectory", type=str, help="Root output directory")

    args = parser.parse_args()

    return (args.inputRootDirectory, args.outputRootDirectory)

def _generateData(inRootFolder, configuration, entryPointScope, entryPointName, entryPointKey):
    """
    Generates the data used to build the parser from the various input files
    provided in the input folder.

    Args:
        inRootFolder (str): path to the root input folder.
        configuration (Config): parser configuration information.
        entryPointScope (str): scope of the entry point (top level Object)
            into the parser.
        entryPointName (str): name of the entry point Object for the parser.
        entryPointKey (str): the name of the graph node for the entry point
            Object.

    Returns:
        (dict, zeektypes.ZeekMain, dict, dict, dict, dict, dict): a tuple with
            the following values:
            1. dictionary of Zeek Objects for the parser. the key is the
                logging structure that the object belongs to and the value is
                the object itself.
            2. data and functions class related to generating main.zeek.
            3. a dictionary containing information about cross-scope
                dependencies. the key represents the scope that has
                dependencies. the value is dictionary with keys representing
                the scopes where the dependencies reside. the values are
                dictionaries where the keys are a subset of "enum", "object",
                "custom", and "id". the values of these dictionaries are sets
                with the actual dependency names.
            4. a dictionary of Objects where the key is the scope and the
                value is a dictionary where the key is the name of the Object
                and the value is the Object itself.
            5. a dictionary of Switches where the key is the scope and the
                value is a dictionary where the key is the name of the Switch
                and the value is the Switch itself.
            6. a dictionary of Bitfields where the key is the scope and the
                value is a dictionary where the key is the name of the
                Bitfield and the value is the Bitfield itself.
            7. a dictionary of Enums where the key is the scope and the
                value is a dictionary where the key is the name of the Enum
                and the value is the Enum itself.
    """
    ############################################################################
    # Process the data files
    ############################################################################
    objects, switches, bitfields, enums = processing.loadFiles(inRootFolder, configuration.scopes)

    ############################################################################
    # Use some Graph Theory to our advantage
    ############################################################################
    generation_utils.createAndUseGraphInformation(configuration, objects, switches, bitfields, enums, entryPointScope, entryPointName, entryPointKey)

    ############################################################################
    # Work with the loaded data
    ############################################################################
    zeekTypes, zeekMainFileObject = processing.createZeekObjects(configuration.scopes, configuration.customFieldTypes, bitfields, objects, switches)

    # Determine import requirements
    # currentScope -> dependentScope[] -> ["enum"/"object"/"custom"] -> referenceType[]
    crossScopeItems = generation_utils.determineInterScopeDependencies(configuration, bitfields, objects, switches)

    return (zeekTypes, zeekMainFileObject, crossScopeItems, bitfields, enums, objects, switches)

def determineEntryPointInformation(configuration):
    """
    Determines the entry point information (scope, name, key) given a
    configuration.

    Args:
        configuration (Config): parser configuration information.

    Returns:
        (bool, str, str, str): a tuple with the following values:
            1. whether or not the information was sucessfully determined.
            2. the scope of the entry point (if successful).
            3. the name of the entry point Object (if successful).
            4. the key for the entry point node in the graph (if successful).
    """
    entryPointParts = configuration.entryPoint.split(".")
    if 2 != len(entryPointParts):
        return (False, "", "", "")

    entryPointScope = entryPointParts[0]
    entryPointName = entryPointParts[1]
    entryPointKey = graphing.normalizedKey3(utils.normalizedScope(entryPointScope, "object"), "object", entryPointName)

    return (True, entryPointScope, entryPointName, entryPointKey)

if __name__ == "__main__":
    """
    Main routine for the program. The following code kicks off Parsnip and
    calls the necessarily functions to generate the parser from beginning of
    execution to the end.
    """
    import os

    ############################################################################
    # Parse Command Line Arguments
    ############################################################################
    inRootFolder, outRootFolder = _parseArgs()

    ############################################################################
    # Load the configuration file
    ############################################################################
    configPath = os.path.join(inRootFolder, utils.DEFAULT_SCOPE, "config.json")

    loadSuccessful, configuration = config.loadConfig(configPath)
    if not loadSuccessful:
        print(configPath + " is a required file")
        exit(1)

    _updateUtilValues(configuration)

    entryPointParsingSuccessful, entryPointScope, entryPointName, entryPointKey = determineEntryPointInformation(configuration)

    if not entryPointParsingSuccessful:
        print("EntryPoint must have scope and object name")
        exit(2)

    print(entryPointScope + " ---> " + entryPointName)

    ############################################################################
    # Load and work with data
    ############################################################################
    zeekTypes, zeekMainFileObject, crossScopeItems, bitfields, enums, objects, switches = _generateData(inRootFolder, configuration, entryPointScope, entryPointName, entryPointKey)

    ############################################################################
    # Generate output
    ############################################################################
    generation_utils.writeParserFiles(configuration, outRootFolder,
                                      zeekTypes, zeekMainFileObject,
                                      crossScopeItems,
                                      bitfields, enums,
                                      objects, switches,
                                      entryPointScope, entryPointName)
