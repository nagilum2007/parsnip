#!/usr/bin/env python3

# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds functions and information related to graphing a parser.
"""

# Local Imports
import utils

# Standard Library Imports
import json

################################################################################
# Type Declarations
################################################################################
# Parsnip Supported Language Types
languageTypes = [
    ("addr", [32, 128]), # Passthrough Spicy Type
    ("uint", [8, 16, 24, 32, 64]), # Spicy built in for sizes 8, 16, 32, and 64; 24 we added
    ("int", [8, 16, 24, 32, 64]), # Spicy built in for sizes 8, 16, 32, and 64; 24 we added
    ("void", None), # Spicy type used to denote no fields
    ("bytes", None), # Passthrough Spicy Type, size will be converted to bytes from bits
    ("float", [32, 64]), # Maps to spicy "real" type with either float or double flag
    ("time", None),
    ("date", None)
]

# Types that are specific to bitfields
bitfieldSpecificTypes = ["bool", "uint", "enum"]

# Parsnip structure types
structureTypes = {
    "bits": "Bitfields", # Maps to bitfield structures
    "enum": "Enums", # Maps to enum structures
    "object": "Objects", # Maps to object structures
    "switch": "Switches" # Maps to switches structures
}

# Other types used in Parsnip
otherReferenceTypes = {
    "list" # A list of other types
}

################################################################################
# Function Declarations
################################################################################

# TODO: Do we still need this function?
def loadFile(filePath):
    """
    Loads a JSON file and returns the contents as a Python structure.

    Args:
        filePath (str): Path to the JSON file to load.

    Returns:
        Any: Contents of the file as a Python structure. This is typically as
            a list or dictionary.
    """
    with open(filePath, "r") as file:
        contents = json.load(file)
    return contents

def normalizedKey3(value1, value2, value3):
    """
    Convenience function to generate a 3-value key used in the parser graph.

    Args:
        value1 (str): First part of the key. Typically the item scope.
        value2 (str): Second part of the key. Typically the item type.
        value3 (str): Third part of the key. Typically the item name.

    Returns:
        str: The key used in the parser graph.
    """
    return "{}.{}.{}".format(value1, value2, value3)

def normalizedType(itemType, referenceScope, referenceType, elementType,
                   itemSize, isReference, userDefinedTypes):
    """
    Normalizes the type of an item based on the information for an item. This
    is used to create a consistent label for elements of a graph.

    Args:
        itemType (str): The item type.
        referenceScope (str): The scope of the item.
        referenceType (str): The name of the item being referenced.
        elementType (str): The type of the elements when itemType is "list".
        itemSize (str): The size of the item in bits.
        isReference (bool): True if the item is a reference. Otherwise False.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.

    Returns:
        (None|str, None|str, bool): A tuple with the following values:
            1. None or the normalized item type.
            2. None or the key for the item referenced.
            3. Whether or not the item is a list.
    """
    returnValue = ""
    denoteReference = False
    isList = False
    returnReference = None
    if None == itemType:
        returnValue = None
    elif "object" == itemType:
        returnValue = "Object"
        denoteReference = isReference
        if isReference:
            returnReference = normalizedKey3(referenceScope, itemType, referenceType)
    elif "bits" == itemType:
        returnValue = "Bitfield"
        denoteReference = isReference
        if isReference:
            returnReference = normalizedKey3(referenceScope, itemType, referenceType)
    elif "enum" == itemType:
        returnValue = "Enum"
        denoteReference = isReference
        if isReference:
            returnReference = normalizedKey3(referenceScope, itemType, referenceType)
    elif "switch" == itemType:
        returnValue = "Switch"
        denoteReference = isReference
        if isReference:
            returnReference = normalizedKey3(referenceScope, itemType, referenceType)
    elif "user" == itemType:
        returnValue = "UserType"
        denoteReference = isReference
    elif "list" == itemType:
        returnValue, returnReference, isList = \
            normalizedType(elementType, referenceScope, referenceType, None,
                           itemSize, isReference, userDefinedTypes)
        returnValue += "[]"
        isList = True
    elif itemType in userDefinedTypes:
        returnValue = itemType + "(" + str(itemSize) + ")"
        returnReference = itemType
    elif itemType in bitfieldSpecificTypes:
        returnValue = itemType
    else:
        typeIndex = next((index for index, value in enumerate(languageTypes) if value[0] == itemType), -1)
        if typeIndex != -1:
            returnValue = itemType
            # This is a known type
            if itemSize is not None:
                returnValue += str(itemSize)
        else:
            print("Unhandled Type: {} {} {}".format(itemType, elementType,
                                                    itemSize))

    if denoteReference:
        returnValue += "Reference"
    return (returnValue, returnReference, isList)

def normalizedLabel(itemType, referenceScope, referenceType, elementType,
                    itemSize, itemName, isReference, userDefinedTypes):
    """
    A normalized label for an item.

    Args:
        itemType (str): The item type.
        referenceScope (str): The scope of the item.
        referenceType (str): The name of the item being referenced.
        elementType (str): The type of the elements when itemType is "list".
        itemSize (str): The size of the item in bits.
        itemName (str): The name of the item.
        isReference (bool): True if the item is a reference. Otherwise False.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.

    Returns:
        (str, None|str, bool): A tuple with the following values:
            1. The normalized label.
            2. None or the key for the referenced item.
            3. Whether or not the item is a list.
    """
    returnType, returnReference, isList = \
        normalizedType(itemType, referenceScope, referenceType, elementType, itemSize,
                       isReference, userDefinedTypes)
    preString = ""
    if returnType is not None:
        preString = "{}:".format(returnType)
    return ('"{}{}"'.format(preString, itemName), returnReference, isList)

def addUserTypeNode(userType, nodeInformation, metaData, userDefinedTypes):
    """
    Adds a user type node to the graph.

    Args:
        userType (str): The name of the type.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        metaData (dict): Metadata information to attach to the node.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.
    """
    label, _, _ = normalizedLabel("user", None, None, None, None, userType, False,
                                  userDefinedTypes)
    nodeInformation[userType] = (label, metaData)

def _valueOrDefault(item, key, default):
    """
    Returns the value of a key if it exists, otherwise a supplied default
    value.

    Args:
        item (dict): The dictionary where the key may exist.
        key (str): The key to find in the item.
        default (Any): The value to return if the key doesn't exist in the
            item.

    Returns:
        Any: The value of the key in the item if it exists, otherwise the
            supplied default value.
    """
    if hasattr(item, key):
        return getattr(item, key)
    return default

# TODO: Can we remove unused parameters?
def getItemName(itemScope, item, itemType):
    """
    Provides the name of an item.

    Args:
        itemScope (str): The scope of the item.
        item (Any): The item to get the name of.
        itemType (str): The item type.

    Returns:
        _type_: _description_
    """
    return item.name

def addItemNode(itemScope, item, itemType, nodeInformation, metaData, userDefinedTypes):
    """
    Add an item node to the graph.

    Args:
        itemScope (str): The scope of the item.
        item (Any): The item to add as a node.
        itemType (str): The item type.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        metaData (dict): Metadata information to attach to the node.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.

    Returns:
        str: The name of the item added.
    """
    name = getItemName(itemScope, item, itemType)
    if metaData is None:
        metaData = {}
    metaData["logIndependently"] = _valueOrDefault(item, "logIndependently", False)
    metaData["logWithParent"] = _valueOrDefault(item, "logWithParent", False)
    label, _, _ = normalizedLabel(itemType, None, None, None, None, name, False,
                                  userDefinedTypes)
    nodeReference = normalizedKey3(itemScope, itemType, name)
    nodeInformation[nodeReference] = (label, metaData)
    return name

def normalizedKey2(value1, value2):
    """
    Convenience function to generate a 2-value key used in the parser graph.

    Args:
        value1 (str): First part of the key. Typically the item's parent.
        value2 (str): Second part of the key. Typically the item name.

    Returns:
        str: The key used in the parser graph.
    """
    return "{}.{}".format(value1, value2)

def normalizedKey4(value1, value2, value3, value4):
    """
    Convenience function to generate a 4-value key used in the parser graph.

    Args:
        value1 (str): First part of the key. Typically the item's parent's
            scope.
        value2 (str): Second part of the key. Typically the item's parent's
            type.
        value3 (str): Third part of the key. Typically the item's parent's
            name.
        value4 (str): Forth part of the key. Typically the item name.

    Returns:
        str: The key used in the parser graph.
    """
    return "{}.{}.{}.{}".format(value1, value2, value3, value4)

def _addNodeItem(parentScope, parentType, parentName, item, storage,
                 userDefinedTypes):
    """
    Add a field or dependency node to the graph.

    Args:
        parentScope (str): The scope of the parent item.
        parentType (str): The type of the parent item.
        parentName (str): The name of the parent item.
        item (Any): The item to process and add.
        storage (dict): The dictionary to add the node information to.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.

    Returns:
        (str, str, str|None): A tuple with the following values:
            1. The 3-value key for parent item.
            2. The 4-value key for the item that was added.
            3. None or the key for the item that was referenced.
    """
    labelName = normalizedKey2(parentName, item.name)
    parentKeyName = normalizedKey3(parentScope, parentType, parentName)
    keyName = normalizedKey4(parentScope, parentType, parentName,
                             item.name)
    label, referenceType, isList = \
        normalizedLabel(_valueOrDefault(item, "type", None),
                        _valueOrDefault(item, "scope", None),
                        _valueOrDefault(item, "referenceType", None),
                        _valueOrDefault(item, "elementType", None),
                        _valueOrDefault(item, "size", None), labelName, True,
                        userDefinedTypes)
    metaData = {"isList": isList}
    storage[keyName] = (label, metaData)
    return (parentKeyName, keyName, referenceType)

def _addConnection(source, destination, label, storage):
    """
    Adds directional connection information for a single connection.

    Args:
        source (str): The key that is the source node of the connection.
        destination (str): The key that is the destination node of the
            connection.
        label (str): The label for the connection.
        storage (list): The location to store the connection information.
    """
    storage.append((source, destination, label))

def _addReferenceConnection(itemKey, referenceType, storage):
    """
    Adds directional connection information for a single reference connection.

    Args:
        itemKey (str): The key of the item that has a reference.
        referenceType (str|None): The key of the item type that is referenced.
        storage (list): The location to store the connection information.
    """
    if referenceType is not None:
        _addConnection(itemKey, referenceType, "reference", storage)

def addFieldNode(itemScope, itemType, itemName, field, fieldNameType,
                 nodeInformation, referenceInformation, fieldsInformation,
                 userDefinedTypes):
    """
    Adds a field node and related to connections to the graph.

    Args:
        itemScope (str): The scope of the parent item.
        itemType (str): The item type of the parent item.
        itemName (str): The name of the parent item.
        field (Any): The field to add.
        fieldNameType (str): The type of the field to add.
        nodeInformation (dict): Node information dictionary to save the graph
            nodes to.
        referenceInformation (list): Connection information of connections due
            to types referenced by the objects.
        fieldsInformation (list): Connection information of connections due to
            Object fields.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.
    """
    parentKey, keyName, referenceType = _addNodeItem(itemScope, itemType,
                                                     itemName, field,
                                                     nodeInformation,
                                                     userDefinedTypes)

    _addReferenceConnection(keyName, referenceType, referenceInformation)
    _addConnection(parentKey, keyName, fieldNameType, fieldsInformation)

def addDependencyNode(itemScope, itemType, itemName, dependency,
                      dependencyNodeInformation, depedencyReferenceInformation,
                      dependencyInformation, userDefinedTypes):
    """
    Adds a dependency node and related connections to the graph.

    Args:
        itemScope (str): The scope of the parent item.
        itemType (str): The item type of the parent item.
        itemName (str): The name of the parent item.
        dependency (Any): The dependency to add
        dependencyNodeInformation (dict): Graph node dictionary to save
            dependency nodes to.
        dependencyReferenceInformation (list): Connection information of
            connections related to the dependency nodes.
        dependencyInformation (list): Connection information of connections
            related to dependency fields.
        userDefinedTypes (list): List of user-defined types associated with
            the parser.
    """
    parentKey, keyName, referenceType = _addNodeItem(itemScope, itemType,
                                                     itemName, dependency,
                                                     dependencyNodeInformation,
                                                     userDefinedTypes)
    _addReferenceConnection(keyName, referenceType,
                            depedencyReferenceInformation)
    _addConnection(parentKey, keyName, "dependency", dependencyInformation)
