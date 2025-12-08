# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds global/utility (constant) values and functions used by other
files in the project.
"""

import re
from math import ceil

# The number of spaces to use for a "tab"
TAB_SIZE = 4
# A string constant for a single tab worth of space.
SINGLE_TAB = " " * TAB_SIZE
# A string constant for a double tabe worth of space.
DOUBLE_TAB = SINGLE_TAB * 2
# The name of the protocol. This is updated based on the parser configuration.
PROTOCOL_NAME = ""
# The name of the default scope.
DEFAULT_SCOPE = "general"
# The name of the conversion scope. This scope holds conversion functions.
CONVERSION_SCOPE = "conversion"
# The name of the ID scope. This scope holds ID generation functions.
ID_SCOPE = "generateid"
# Whether or not the parser uses Layer 2. This is updated based on the parser
# configuration.
USES_LAYER_2 = False

# Global dictionary of scopes having links across scopes.
scopesHaveCrossScopeLinks = {}

def getTabString(tabs):
    """
    Returns a string of spaces with a number of spaces equal to the TAB_SIZE
    multiplied by tabs.

    Args:
        tabs (int): the number of tabs to generate the spaces for.

    Returns:
        str: a string of spaces for the requested number of tabs.
    """
    return SINGLE_TAB * tabs

# Dictionary where the keys are the Spicy types and the values are the
# corresponding Zeek types.
spicyToZeek = {
    "addr"      : "addr",
    "uint"      : "count",
    "uint8"     : "count",
    "uint16"    : "count",
    "uint32"    : "count",
    "uint64"    : "count",
    "int8"      : "int",
    "int16"     : "int",
    "int32"     : "int",
    "int64"     : "int",
    "int"       : "int",
    "bool"      : "bool",
    "real"      : "double",
    "string"    : "string",
    "enum"      : "string",
    "float"     : "double",
    "bytes"     : "string",
    "time"      : "time"
}

# A dictionary of the custom field types used by the parser. This is updated
# based on the parser configuration.
customFieldTypes = {}

def zeekTypeMapping(spicyType):
    """
    Maps a Spicy Type to a Zeek Type.

    Args:
        spicyType (str): the Spicy type to map.

    Returns:
        str: the Zeek type if the Spicy type maps to one, otherwise the Spicy
            type.
    """
    if spicyType in spicyToZeek:
        return spicyToZeek[spicyType]
    else:
        print("Unknown type {0}".format(spicyType))
        return spicyType

def commandNameToConst(commandName):
    """
    Determines the normalized constant name for a command name.

    Args:
        commandName (str): the command name to normalize as a constant.

    Returns:
        str: the normalized constant name for the command name.
    """
    name = re.sub(r'(.)([A-Z][a-z]+)', r'\1_\2', commandName)
    return re.sub(r'([a-z0-9])([A-Z])', r'\1_\2', name)

def calculateColumn(nameLength):
    """
    Determines the tab-aligned column for a given length.

    Args:
        nameLength (int): the length to figure out the tab-aligned column for.

    Returns:
        int: the tab-aligned column for the given length.
    """
    return ceil((nameLength + 1) / TAB_SIZE) * TAB_SIZE

def endingSpace(columns, nameLength):
    """
    Generates a string of spaces to add to the end of a name to have it aligned
    with the desired number of columns.

    Args:
        columns (int): the target column.
        nameLength (int): the length of the current name.

    Returns:
        str: the string of spaces to add to the end of a name to have it
            aligned with the desired number of columns.
    """
    return " " * (columns - nameLength)

def normalizedScope(scope, itemType):
    """
    Generates a normalized scope given a non-normalized or normalized scope and
    an item type.

    Args:
        scope (str): the scope to normalize.
        itemType (str): the type of item associated with the scope.

    Returns:
        str: the normalized scope.
    """
    if scope == "general" or PROTOCOL_NAME.upper() == scope:
        if "enum" == itemType:
            return PROTOCOL_NAME.upper() + "_ENUM"
        else:
            return PROTOCOL_NAME.upper()
    elif scope != "":
        if "enum" == itemType:
            scope = scope + "_enum"
        return PROTOCOL_NAME.upper() + "_" + scope.upper()
    else:
        return ""

def loggingParentScope(scope):
    """
    Provides the logging scope to associate with a given scope.

    Args:
        scope (str): the scope to provide the logging scope for.

    Returns:
        str: the logging scope to use.
    """
    if scope == "general" or PROTOCOL_NAME.upper() == scope:
        return "general"
    elif scope.startswith(PROTOCOL_NAME.upper()):
        temp = scope[len(PROTOCOL_NAME.upper()) + 1:]
        return temp.lower()
    else:
        print("Unexepected scope: {}".format(scope))
        return scope

def determineSpicyStringForAction(action, switch, inputs, actionColumn, customTypes, bitfields, switches, enums):
    """
    Determines and generates the Spicy code to use for an action.

    Args:
        action (switches.SwitchAction): the action to create the Spicy code
            for.
        switch (switches.Switch): the switch the action is associated with.
        inputs (list): the array of inputs. Input structures that are the
            inputs for the switch.
        actionColumn (int): the column to align the action to.
        customTypes (dict): the dictionary of any custom types used by the
            parser.
        bitfields (dict): dictionary of all Bitfields for the parser
            broken down by scope, followed by the name of the Bitfield.
        switches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        enums (dict): dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        str: the spicy code to use for the action.
    """
    if "void" == action.type:
        return "{0} : void".format(endingSpace(actionColumn, 0))
    mappedUntilValue = None
    if action.until is not None:
        mappedUntilValue = action.until
        if mappedUntilValue.get("indicator") is not None:
            if switch.dependsOn is not None and switch.dependsOn.name == mappedUntilValue.get("indicator"):
                mappedUntilValue["indicator"] = inputs[0].source
            else:
                for dependencyIndex in range(len(switch.additionalDependsOn)):
                    if switch.additionalDependsOn[dependencyIndex].name == mappedUntilValue.get("indicator"):
                        mappedUntilValue["indicator"] = inputs[1 + dependencyIndex].source
                        if inputs[1 + dependencyIndex].minusInUse:
                            mappedUntilValue["minus"] = inputs[1 + dependencyIndex].minus
                        elif "minus" in mappedUntilValue:
                            # TODO: Figure out how mappedUntilValue is holding onto old data
                            del mappedUntilValue["minus"]
                        break
    tempInputs = []
    for input in action.inputs:
        if switch.dependsOn is not None and switch.dependsOn.name == input.source:
            tempInputs.append(inputs[0])
        else:
            for dependencyIndex in range(len(switch.additionalDependsOn)):
                if switch.additionalDependsOn[dependencyIndex].name == input.source:
                    tempInputs.append(inputs[1 + dependencyIndex])
                    break
    _, typeString = determineSpicyStringForType(action.name, action.type, action.elementType, action.referenceType, action.scope, action.size, tempInputs, mappedUntilValue, actionColumn, customTypes, bitfields, switches, enums)
    return "{0}{1} : {2}".format(action.name, endingSpace(actionColumn, len(action.name)), typeString)

def _returnIntegerType(itemType, size, columns, itemName):
    """
    Generates the Spicy code to parse an integer type.

    Args:
        itemType (str): type of integer. should be in ["int", "uint"].
        size (int): the size of the integer. should be in [8, 16, 24, 32, 64].
        columns (int): the column to align the string to.
        itemName (str): the variable name.

    Returns:
        (str, str): a tuple with the following values:
            1. the string to use for a variable declaration (if needed).
            2. the string to use for doing conversions (if needed).

            both return values are empty if incorrect values are passed in.
    """
    if size in [8, 16, 32, 64]:
        return ("", itemType + str(size))
    elif 24 == size:
        sizeInBytes = int(ceil(size / 8))
        returnString = "bytes &size={0} {{\n".format(sizeInBytes)
        returnString += "{0}{1}   self.{2} = $$.to_uint(spicy::ByteOrder::Big);\n".format(DOUBLE_TAB, endingSpace(columns, 0), itemName)
        returnString += "{0}{1}   }}".format(SINGLE_TAB, endingSpace(columns, 0))

        return (itemType + "64", returnString)
    else:
        print("Current unsupported (u)int size {0}".format(size))
        return ("","")

def _returnSpicyObjectType(itemType, enums, scope, referenceType, inputs):
    """
    Generates the Spicy code to parse an Object or Enum.

    Args:
        itemType (str): the type of item to process.
        enums (dict): dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        scope (str): the normalized scope being processed.
        referenceType (str): the name of the item being processed.
        inputs (list): the array of inputs. Input structures that are the
            inputs for the item.

    Returns:
        (str, str): a tuple with the following values:
            1. an empty string.
            2. the string to use for the converting/processing the item in the
                Spicy code.
    """
    outputString = ""
    if "enum" == itemType:
        reference = enums[scope][referenceType]
        outputString += "uint{0}".format(reference.size)
        if "little" == reference.endianness:
            outputString += " &byte-order=spicy::ByteOrder::Little"
        outputString += " &convert="
    outputString += "{0}::{1}".format(scope, referenceType)

    if "enum" == itemType:
        outputString += "($$)"
    elif 0 < len(inputs):
        outputString += "("
        for index, value in enumerate(inputs):
            outputString += value.getString()
            if index < len(inputs) - 1:
                outputString += ", "
        outputString += ")"
    return ("", outputString)

# function for converting to time type
def _returnTimeType(size):
    """
    Generates the Spicy code to parse a time type.

    Args:
        size (int): the size of the time type. should be 32.

    Returns:
        (str, str): a tuple with the following values:
        1. an empty string.
        2. The string to use for converting/processing the item in the Spicy
            code.
    """
    if size == 32:
        return ("", "uint32 &convert=cast<time>($$)")
    #elif size == 64:
    #    return ("", "uint64 &convert=cast<time>($$)")
    else:
        print("Currently unknown time size {0}".format(size))
        return ("", "")

def _returnFloatType(size):
    """
    Generates the Spicy code to parse a float type.

    Args:
        size (int): the size of the float type. should be in [32, 64].

    Returns:
        (str, str): a tuple with the following values:
            1. an empty string.
            2. the string to use for converting the item (if one exists) in
                the Spicy code.
    """
    if 32 == size:
        return ("", "real &type=spicy::RealType::IEEE754_Single")
    elif 64 == size:
        return ("", "real &type=spicy::RealType::IEEE754_Double")
    else:
        print("Currently unknown float size {0}".format(size))
        return ("", "")

def _returnAddrType(size):
    """
    Generates the Spicy code to parse an address type.

    Args:
        size (int): the size of the address. should be in [32, 128].

    Returns:
        (str, str): a tuple with the following values:
            1. an empty string.
            2. the string to use for converting the item (if one exists) in the
                Spicy code.
    """
    if size == 32:
        return ("", "addr &ipv4")
    elif size == 128:
        return ("", "addr &ipv6")
    else:
        print("Currently unknown addr size {0}".format(size))
        return ("", "")

def _returnBitsType(bitfields, scope, referenceType, columns):
    """
    Generates the Spicy code to parse a Bitfield type.

    Args:
        bitfields (dict): dictionary of all Bitfields for the parser
            broken down by scope, followed by the name of the Bitfield.
        scope (str): the normalized scope being processed.
        referenceType (str): the name of the item being processed.
        columns (int): the column to align the string to.

    Returns:
        (str, str): a tuple with the following values:
            1. an empty string.
            2. the string to use for processing the Bitfield in the Spicy code.
    """
    # Have to get size from the reference
    reference = bitfields[scope][referenceType]
    outputString = "bitfield({0}) {{\n".format(reference.size)
    for field in reference.fields:
        if field.notes is not None and "" != field.notes:
            outputString += "{0}{1}   # {2}\n".format(DOUBLE_TAB, endingSpace(columns, 0), field.notes)
        conversionString = ""
        if "enum" == field.type:
            conversionString = " &convert={0}::{1}($$)".format(field.scope, field.referenceType)
        elif "bool" == field.type:
            conversionString = " &convert=cast<bool>($$)"
        outputString += "{0}{1}   {2}{3} : {4}{5};\n".format(DOUBLE_TAB, endingSpace(columns, 0), field.name, endingSpace(reference.column, len(field.name)), field.bits, conversionString)
    outputString += "{0}{1}   }}".format(SINGLE_TAB, endingSpace(columns, 0))
    if "little" == reference.endianness:
        outputString += " &byte-order=spicy::ByteOrder::Little"
    return ("", outputString)

def _returnListType(itemName, elementType, referenceType, scope, size, inputs, customTypes, bitfields, switches, enums, until):
    """
    Generates the Spicy code to parse a List type.

    Args:
        itemName (str): the variable name.
        elementType (str): the type of the elements.
        referenceType (str): the name of the item being processed.
        scope (str): the normalized scope being processed.
        size (int): the size (in bits) of the field if the associated type
            requires a size.
        inputs (list): the array of inputs. Input structures that are the
            inputs for the item.
        customTypes (dict): the dictionary of any custom types used by the
            parser.
        bitfields (dict): dictionary of all Bitfields for the parser
            broken down by scope, followed by the name of the Bitfield.
        switches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        enums (dict): dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.
        until (dict): the until statement in dictionary format.

    Returns:
        (str, str): a tuple with the following values:
            1. the string to use for a variable declaration (if needed).
            2. the string to use for doing conversions (if needed).
    """
    varString, typeString = determineSpicyStringForType(itemName, elementType, None, referenceType, scope, size, inputs, None, 0, customTypes, bitfields, switches, enums)
    sizeString = ""
    conditionString = ""
    if until is not None and until.get("conditionType") is not None:
        conditionType = until.get("conditionType")
        if "ENDOFDATA" == conditionType:
            conditionString = " &eod"
        elif "COUNT" == conditionType:
            sizeString = until.get("indicator")
            if until.get("minus") is not None:
                sizeString = "({} - {})".format(sizeString, until.get("minus"))
        elif "BYTECOUNT" == conditionType:
            conditionString = " &until="
            indicator = until.get("indicator")
            if until.get("minus") is None:
                conditionString += indicator
            else:
                conditionString += "({} - {})".format(indicator, until.get("minus"))
        else:
            print("Unknown list condition type of {0}".format(conditionType))
    typeString = "({0})[{1}]{2}".format(typeString, sizeString, conditionString)

    return (varString, typeString)

def _returnSwitchType(scope, referenceType, inputs, customTypes, bitfields, switches, enums):
    """
    Generates the Spicy code to add a Switch type.

    Args:
        scope (str): the normalized scope being processed.
        referenceType (str): the name of the item being processed.
        inputs (list): the array of inputs. Input structures that are the
            inputs for the item. the first item is used as the primary input
            for the Switch.
        customTypes (dict): the dictionary of any custom types used by the
            parser.
        bitfields (dict): dictionary of all Bitfields for the parser
            broken down by scope, followed by the name of the Bitfield.
        switches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        enums (dict): dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        (str, str): a tuple with the following values:
            1. an empty string.
            2. the string that represents the switch.
    """
    reference = switches[scope][referenceType]
    outputString = "switch({0}) {{\n".format(inputs[0].getString())
    for option in reference.options:
        if option.action.type != "void":
            preString = ""
            if "enum" == reference.dependsOn.type:
                preString = "{0}::{1}::".format(reference.dependsOn.scope, reference.dependsOn.referenceType)
            outputString += "{0}{1}{2}{3} -> {4};\n".format(DOUBLE_TAB, preString, option.value, endingSpace(reference.column, len(str(option.value))), determineSpicyStringForAction(option.action, reference, inputs, reference.actionColumn, customTypes, bitfields, switches, enums))
    defaultActionString = "{0} : void".format(endingSpace(reference.actionColumn, 0))
    if reference.default is not None:
        defaultActionString = determineSpicyStringForAction(reference.default, reference, inputs, reference.actionColumn, customTypes, bitfields, switches, enums)
    outputString += "{0}*{1}{2} -> {3};\n".format(DOUBLE_TAB, " "*len(preString), endingSpace(reference.column, 1), defaultActionString)
    outputString += "{0}}}".format(SINGLE_TAB)
    return ("", outputString)

def determineSpicyStringForType(itemName, itemType, elementType, referenceType, scope, size, inputs, until, columns, customTypes, bitfields, switches, enums):
    """
    Generates the Spicy code needed for a given type.

    Args:
        itemName (str): the variable name.
        itemType (str): the type of item to process.
        elementType (str): the type of the elements if the itemType is "list".
        referenceType (str): the name of the item being processed if the
            itemType or elementType is of "object", "enum", "bits", or
            "switch".
        scope (str): the normalized scope being processed.
        size (int): the size (in bits) of the field if the associated type
            requires a size.
        inputs (list): the array of inputs. Input structures that are the
            inputs for the item. the first item is used as the primary input
            for the Switch.
        until (dict): the until statement in dictionary format.
        columns (int): the column to align the string to.
        customTypes (dict): the dictionary of any custom types used by the
            parser.
        bitfields (dict): dictionary of all Bitfields for the parser
            broken down by scope, followed by the name of the Bitfield.
        switches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        enums (dict): dictionary of all Enums for the parser broken down
            by scope, followed by the name of the Enum.

    Returns:
        (str, str): a tuple with the following values:
            1. the string to use for a variable declaration (if needed).
            2. the string to use for doing conversions or processing (if needed).
    """
    if itemType in ["uint", "int"]:
        return _returnIntegerType(itemType, size, columns, itemName)
    elif itemType in ["object", "enum"]:
        return _returnSpicyObjectType(itemType, enums, scope, referenceType, inputs)
    elif "bytes" == itemType:
        return ("", "bytes &size={0}".format(int(ceil(size / 8))))
    elif "float" == itemType:
        return _returnFloatType(size)
    elif "addr" == itemType:
        return _returnAddrType(size)
    elif "bits" == itemType:
        return _returnBitsType(bitfields, scope, referenceType, columns)
    elif "list" == itemType:
        return _returnListType(itemName, elementType, referenceType, scope, size, inputs, customTypes, bitfields, switches, enums, until)
    elif "string" == itemType:
        return ("", "string")
    elif "switch" == itemType:
        return _returnSwitchType(scope, referenceType, inputs, customTypes, bitfields, switches, enums)
    elif "time" == itemType: # added handler for time
        return _returnTimeType(size)  # assumes 32-bit time in seconds
    elif itemType in customTypes:
        # See if it's custom type
        sizeInBytes = int(ceil(size / 8))
        return ("", "bytes &size={0} &convert={1}::{2}($$)".format(sizeInBytes, normalizedScope(CONVERSION_SCOPE, ""), customTypes[itemType].interpretingFunction))
    else:
        # Otherwise we don't know...
        print("Currently unknown itemType of {0}".format(itemType))
        return ("", "")

def getObject(referenceType, scopes, allObjects):
    """
    Convenience Function to get the Object and Scope of a particular Object
    reference type without knowing the scope the Object is in.

    Args:
        referenceType (str): the name of the Object.
        scopes (list): an array of strings with the scope names used within
            the parser.
        allObjects (dict): dictionary of all Objects for the parser broken
            down by scope, followed by the name of the Object.

    Returns:
        (objects.Object|None, str|None): a tuple with the following values:
            1. the Object that corresponds to referenceType if found.
                otherwise None.
            2. the scope of the Object if found.
                otherwise None.
    """
    referencedObject = None
    objectScope = None
    for scope in scopes:
        if referenceType in allObjects[normalizedScope(scope, "object")]:
                referencedObject = allObjects[normalizedScope(scope, "object")][referenceType]
                objectScope = scope
                break
    return referencedObject, objectScope

