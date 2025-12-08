# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds functions related to reading the json files associated with
Parsnip.
"""

# This file contains functions for reading each json file type
import json
import enums
import objects
import inputs
import switches
import bitfields
import zeektypes
import utils
import os

def loadFiles(rootFilePath, scopes):
    """
    Opens and loads information from expected Parsnip-related files from
    parser scope directories.

    Args:
        rootFilePath (str): path to the root directory where the scope
            directories are located.
        scopes (list): list of scope names that have directories in the root
            directory.

    Returns:
        (dict, dict, dict, dict): a tuple with the following values:
            1. a dictionary of Objects where the key is the scope and the
                value is a dictionary where the key is the name of the Object
                and the value is the Object itself.
            2. a dictionary of Switches where the key is the scope and the
                value is a dictionary where the key is the name of the Switch
                and the value is the Switch itself.
            3. a dictionary of Bitfields where the key is the scope and the
                value is a dictionary where the key is the name of the
                Bitfield and the value is the Bitfield itself.
            4. a dictionary of Enums where the key is the scope and the
                value is a dictionary where the key is the name of the Enum
                and the value is the Enum itself.
    """
    objects = {}
    switches = {}
    bitfields = {}
    enums = {}

    for scope in scopes:
        objectFilePath = os.path.join(rootFilePath, scope, "objects.json")
        switchesFilePath = os.path.join(rootFilePath, scope, "switches.json")
        bitfieldsFilePath = os.path.join(rootFilePath, scope, "bitfields.json")
        enumsFilePath = os.path.join(rootFilePath, scope, "enums.json")

        if os.path.isfile(objectFilePath):
            print("Processing {0}".format(objectFilePath))
            objects[utils.normalizedScope(scope, "object")] = processObjectsFile(objectFilePath, scope)
        if os.path.isfile(switchesFilePath):
            print("Processing {0}".format(switchesFilePath))
            switches[utils.normalizedScope(scope, "switch")] = processSwitchFile(switchesFilePath)
        if os.path.isfile(bitfieldsFilePath):
            print("Processing {0}".format(bitfieldsFilePath))
            bitfields[utils.normalizedScope(scope, "bitfield")] = processBitfieldFile(bitfieldsFilePath)
        if os.path.isfile(enumsFilePath):
            print("Processing {0}".format(enumsFilePath))
            enums[utils.normalizedScope(scope, "enum")] = processEnumFile(enumsFilePath)

    return (objects, switches, bitfields, enums)

def passThroughLink(switchName, objectField, scopes, allObjects, allSwitches, linkObjectField):
    """
    Adds a linking ID dependency to all options in a specified switch if that
    switch is the only field in an object.

    Args:
        switchName (str): the name of the switch to process.
        objectField (objects.ObjectField): the ObjectField that references the
            switch.
        scopes (list): an array of strings with the scope names used within the
            parser.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        allSwitches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        linkObjectField (objects.Link): the linking field to add.
    """
    for scope in scopes:
        if switchName in allSwitches[utils.normalizedScope(scope, "")]:
            switch = allSwitches[utils.normalizedScope(scope, "")][switchName]
            break
    if switch != None:
        for item in switch.options:
            objectName = item.action.referenceType
            for scope in scopes:
                if objectName in allObjects[utils.normalizedScope(scope, "")]:
                    object = allObjects[utils.normalizedScope(scope, "")][objectName]
                    object.addLinkField(linkObjectField)
                    dependencyJson =  {
                            "name": "parentLinkId",
                            "type": "string",
                            "size": 8
                        }
                    newInput = inputs.Input("parentLinkId")
                    objectField.addInput(newInput)
                    newAdditionalDependency = createDependencyFromJSON(dependencyJson)
                    switch.addAdditionalDependsOn(newAdditionalDependency)
                    object.addDependency(newAdditionalDependency)
                    item.action.addInput(newInput)

def _getSwitchJson(spicyFieldName):
    """
    Generates JSON structures to be used for linking fields as switch and
    object dependencies.

    Args:
        spicyFieldName (str): the link ID field name to use as the switch
            dependency.

    Returns:
        (dict, dict): a tuple with the following values:
            1. the JSON information to use as the dependency for Objects.
            2. the JSON information to use as the dependency for Switches.
    """
    objectDependencyJson =  {
        "name": "parentLinkId",
        "type": "string",
        "size": 8
    }
    switchDependencyJson =  {
        "name": spicyFieldName,
        "type": "string",
        "size": 8
    }

    return (objectDependencyJson, switchDependencyJson)

def _processNonUsageScope(switch, object, item, scope, objectField):
    """
    Generates a linking field object to use when a Switch option refers to an
    Object in another scope.

    Args:
        switch (switches.Switch): the switch to generate the field for.
        object (objects.Object): the object the switch refers to.
        item (switches.SwitchOption): the option within the switch that refers
            to the object.
        scope (str): the scope the object is in.
        objectField (objects.ObjectField): the ObjectField that references the
            switch.

    Returns:
        objects.Link: the linking object to use.
    """
    spicyFieldName = switch.dependsOn.name[0].lower() + switch.dependsOn.name[1:] + "LinkID"
    linkObjectField = objects.Link(spicyFieldName, "parentLinkId", True)
    fieldInput = inputs.Input("self." + spicyFieldName)
    objectField.addInput(fieldInput)
    objectDependencyJson, switchDependencyJson = _getSwitchJson(spicyFieldName)
    newAdditionaObjectlDependency = createDependencyFromJSON(objectDependencyJson)
    object.addDependency(newAdditionaObjectlDependency)
    newAdditionalSwitchDependency = createDependencyFromJSON(switchDependencyJson)
    switch.addAdditionalDependsOn(newAdditionalSwitchDependency)
    newInput = inputs.Input(spicyFieldName)
    item.action.addInput(newInput)
    if scope not in utils.scopesHaveCrossScopeLinks:
        utils.scopesHaveCrossScopeLinks[scope] = []
    if spicyFieldName not in utils.scopesHaveCrossScopeLinks:
        utils.scopesHaveCrossScopeLinks[scope].append(spicyFieldName)

    return linkObjectField

def getSwitchType(switchName, objectField, switchUsageScope, scopes, allObjects, allSwitches):
    """
    Determines the type of switch that a switch structure is.

    Args:
        switchName (str): the name of the Switch.
        objectField (objects.ObjectField): the ObjectField that references the
            switch.
        switchUsageScope (str): the scope the switch is being used in.
            i.e., the scope the parent Object is in.
        scopes (list): an array of strings with the scope names used within the
            parser.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        allSwitches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.

    Returns:
        str|None : the type of switch, one of the following values:
            - "trivial"
            - "link"
            - "contained"
            - "invalid"
            - None
    """
    for scope in scopes:
        if switchName in allSwitches[utils.normalizedScope(scope, "")]:
            switch = allSwitches[utils.normalizedScope(scope, "")][switchName]
            break
    isSkippedClass = True
    isSelfContained = True
    linkRequired = False
    if switch != None:
        for item in switch.options:
            if item.action.type in utils.spicyToZeek:
                isSkippedClass = False
                continue
            objectName = item.action.referenceType
            for scope in scopes:
                if objectName in allObjects[utils.normalizedScope(scope, "")]:
                    object = allObjects[utils.normalizedScope(scope, "")][objectName]
                    linkObjectField = None
                    if scope != switchUsageScope:
                        linkRequired = True
                        isSkippedClass = False
                        linkObjectField = _processNonUsageScope(switch, object, item, scope, objectField)
                    if not object.logWithParent:
                        isSelfContained = False
                    else:
                        isSkippedClass = False
                    if not isSkippedClass and linkObjectField != None:
                        if len(object.fields) == 1 and object.fields[0].type == "switch":
                            passThroughLink(object.fields[0].referenceType, object.fields[0], scopes, allObjects, allSwitches, linkObjectField)
                        else:
                            object.addLinkField(linkObjectField)
                    break
        if isSkippedClass:
            return "trivial"
        elif linkRequired:
            return "link"
        elif isSelfContained and not linkRequired:
            return "contained"
        else:
            return "invalid"

def createDependencyFromJSON(dependency):
    """
    Creates a new dependency structure from JSON dependency information input.

    Args:
        dependency (dict): the dependency information in the Parsnip JSON
            format.

    Returns:
        inputs.Dependency: the dependency object.
    """
    if "referenceType" in dependency:
        newDependency = inputs.Dependency(dependency["name"], dependency["type"], 0, dependency["referenceType"], dependency["scope"])
    else:
        newDependency = inputs.Dependency(dependency["name"], dependency["type"], dependency["size"])
    return newDependency

def processEnumFile(file):
    """
    Processes a Parsnip scoped enum file.

    Args:
        file (str): the path to the Parsnip enum file to process.

    Returns:
        dict: a dictionary of the enums processed from the file where the keys
            are the names of the enums and the values are the enums structures.
    """
    enumObject = {}
    with open(file, "r+") as file:
        enumList = json.load(file)
    for enum in enumList:
        newEnum = enums.Enums(enum["name"], enum["reference"], enum["size"])
        if "endianness" in enum:
            newEnum.endianness = enum["endianness"]
        if "notes" in enum:
            newEnum.notes = enum["notes"]
        for field in enum["fields"]:
            enumField = enums.EnumField(field["name"], field["loggingValue"], field["value"])
            if "notes" in field:
                enumField.notes = field["notes"]
            newEnum.addField(enumField)
        enumObject[enum["name"]] = newEnum
    return enumObject

def _processConditional(conditional, startingIndex):
    """
    Processes a conditional statement in a Parsnip JSON file and creates a
    tokenized array version of the statement. The conditional can either be a
    basic conditional or a complex conditional.

    Args:
        conditional (dict): JSON object (dictionary) version of the
            conditional.
        startingIndex (int): starting index of the conditional. used for
            calculating offsets, particularly in complex conditionals. on
            initial call, this should be set to 0.

    Returns:
        list: array of token entries for the conditional. each token entry is
            a tuple with the following values:
            1. token identifier.
            2. string value.
            3. (if token identifier is "indicator") offset of indicator.
    """
    if "indicator" in conditional and "operator" in conditional and "value" in conditional:
        return _processRegularConditional(conditional, startingIndex)
    elif "and" in conditional:
        return _processJoiningConditional(conditional, "and", "&&", startingIndex)
    elif "or" in conditional:
        return _processJoiningConditional(conditional, "or", "||", startingIndex)
    else:
        print("Unrecognized conditional")
        return []

def _processRegularConditional(conditional, startingIndex):
    """
    Generates a token string for a basic (i.e., non-complex) conditional
    statement.

    Args:
        conditional (dict): JSON object (dictionary) version of the
            conditional.
        startingIndex (int): starting index of the conditional.

    Returns:
        list: array of token entries for the conditional. each token entry is
            a tuple with the following values:
            1. token identifier.
            2. string value.
            3. (if token identifier is "indicator") offset of indicator.
    """
    return [("indicator", conditional["indicator"], startingIndex + 4),
            ("space", " "),
            ("operator", conditional["operator"]),
            ("space", " "),
            ("value", conditional["value"])]

def _processJoiningConditional(conditional, key, joiner, startingIndex):
    """
    Generates a token string for conditionals involving "ands" or "ors".

    Args:
        conditional (dict): JSON object (dictionary) version of the
            conditional.
        key (str): the token identifier to use for the joiner string.
        joiner (str): the string value to use for the joiner.
        startingIndex (int): starting index of the conditional.

    Returns:
        list: array of token entries for the conditional. each token entry is
            a tuple with the following values:
            1. token identifier.
            2. string value.
            3. (if token identifier is "indicator") offset of indicator.
    """
    returnValue = []
    if startingIndex > 0:
        returnValue.append(("start parantheses", "("))

    for index, value in enumerate(conditional[key]):
        returnValue.extend(_processConditional(value, startingIndex + len(returnValue)))
        if index < len(conditional[key]) - 1:
            returnValue.extend(
                [("space", " "),
                 (key, joiner),
                 ("space", " ")])

    if startingIndex > 0:
        returnValue.append(("end parantheses", ")"))

    return returnValue

def processConditional(conditional):
    """
    Generates a token string for a conditional from a Parsnip JSON file.

    Args:
        conditional (dict): JSON object (dictionary) version of the
            conditional.

    Returns:
        list: array of token entries for the conditional. each token entry is
            a tuple with the following values:
            1. token identifier.
            2. string value.
            3. (if Token Identifier is "indicator") offset of indicator.
    """
    return _processConditional(conditional, 0)

def processObjectsFile(file, scope):
    """
    Processes a Parsnip scoped object file.

    Args:
        file (str): the path to the Parsnip object file to process.
        scope (str): the non-normalized scope being processed.

    Returns:
        dict: a dictionary of the objects processed from the file where the
            keys are the names of the objects and the values are the objects.
    """
    objectsDictionary = {}
    with open(file, "r+") as file:
        objectsList = json.load(file)
    for object in objectsList:
        if "logWithParent" in object:
            newObject = objects.Object(object["name"], object["reference"], object["notes"], object["logIndependently"], object["referenceCount"], scope, object["logWithParent"])
        else:
            newObject = objects.Object(object["name"], object["reference"], object["notes"], object["logIndependently"], object["referenceCount"], scope)
        if "dependsOn" in object:
            for dependency in object["dependsOn"]:
                newDependency = createDependencyFromJSON(dependency)
                newObject.addDependency(newDependency)
        for field in object["fields"]:
            if "scope" in field:
                newField = objects.ObjectField(field["name"], field["description"], field["type"], field["scope"])
            else:
               newField = objects.ObjectField(field["name"], field["description"], field["type"])
            if "referenceType" in field:
                newField.referenceType = field["referenceType"]
            if "elementType" in field:
                newField.elementType = field["elementType"]
            if "until" in field:
                newField.until = field["until"]
            if "size" in field:
                newField.size = field["size"]
            if "notes" in field:
                newField.notes = field["notes"]
            if "input" in field:
                minus = ""
                if "minus" in field["input"]:
                    minus = field["input"]["minus"]
                newInput = inputs.Input(field["input"]["source"], minus)
                newField.addInput(newInput)
            if "inputs" in field:
                for input in field["inputs"]:
                    minus = ""
                    if "minus" in input:
                        minus = input["minus"]
                    newInput = inputs.Input(input["source"], minus)
                    newField.addInput(newInput)
            if "additionalInputs" in field:
                for input in field["additionalInputs"]:
                    minus = ""
                    if "minus" in input:
                        minus = input["minus"]
                    newInput = inputs.Input(input["source"], minus)
                    newField.addInput(newInput)
            if "endianness" in field:
                newField.endianness = field["endianness"]
            if "conditional" in field:
                newField.conditional = processConditional(field["conditional"])
            newObject.addField(newField)
        objectsDictionary[object["name"]] = newObject
    return objectsDictionary

def processSwitchFile(file):
    """
    Processes a Parsnip scoped switch file.

    Args:
        file (str): the path to the Parsnip switch file to process.

    Returns:
        dict: a dictionary of the switches processed from the file where the
            keys are the names of the switches and the values are the
            switch structures.
    """
    switchDictionary = {}
    with open(file, "r+") as file:
        switchList = json.load(file)
    for switch in switchList:
        newSwitch = switches.Switch(switch["name"], switch["referenceCount"])
        newDependency = createDependencyFromJSON(switch["dependsOn"])
        newSwitch.dependsOn = newDependency
        if "additionalDependsOn" in switch:
            for additionalDependency in switch["additionalDependsOn"]:
                newAdditionalDependency = createDependencyFromJSON(additionalDependency)
                newSwitch.addAdditionalDependsOn(newAdditionalDependency)
        for option in switch["options"]:
            newSwitchOption = switches.SwitchOption(option["value"])
            newSwitchAction = switches.SwitchAction(option["action"]["name"], option["action"]["type"], option["action"]["referenceType"] if "referenceType" in option["action"] else "", option["action"]["scope"] if "scope" in option["action"] else "")
            if "size" in option["action"]:
                newSwitchAction.size = option["action"]["size"]
            if "inputs" in option["action"]:
                for input in option["action"]["inputs"]:
                    minus = ""
                    if "minus" in input:
                        minus = input["minus"]
                    newInput = inputs.Input(input["source"], minus)
                    newSwitchAction.addInput(newInput)
            if "elementType" in option["action"]:
                newSwitchAction.elementType = option["action"]["elementType"]
            if "until" in option["action"]:
                newSwitchAction.until = option["action"]["until"]
            newSwitchOption.action = newSwitchAction
            newSwitch.addOption(newSwitchOption)
        if "default" in switch:
            tempAction = switch["default"]
            defaultAction = switches.SwitchAction(tempAction["name"], tempAction["type"], tempAction["referenceType"] if "referenceType" in tempAction else "", tempAction["scope"] if "scope" in tempAction else "")
            if "size" in tempAction:
                defaultAction.size = tempAction["size"]
            if "inputs" in tempAction:
                for input in tempAction["inputs"]:
                    minus = ""
                    if "minus" in input:
                        minus = input["minus"]
                    newInput = inputs.Input(input["source"], minus)
                    defaultAction.addInput(newInput)
            if "elementType" in tempAction:
                defaultAction.elementType = tempAction["elementType"]
            if "until" in tempAction:
                defaultAction.until = tempAction["until"]
            newSwitch.default = defaultAction
        switchDictionary[switch["name"]] = newSwitch
    return switchDictionary

def processBitfieldFile(file):
    """
    Processes a Parsnip scoped bitfield file.

    Args:
        file (str): the path to the Parsnip bitfield file to process.

    Returns:
        dict: a dictionary of the bitfields processed from the file where the
            keys are the names of the bitfields and the values are the
            bitfield structures.
    """
    bitfieldDictionary = {}
    with open(file, "r+") as file:
        bitfieldList = json.load(file)
    for bitfield in bitfieldList:
        newBitfield = bitfields.Bitfield(bitfield["name"], bitfield["reference"], bitfield["notes"], bitfield["size"])
        if "endianness" in bitfield:
            newBitfield.endianness = bitfield["endianness"]
        for field in bitfield["fields"]:
            if "scope" in field:
                newField = bitfields.BitfieldField(field["name"], field["description"], field["type"], field["bits"], field["scope"])
            else:
               newField = bitfields.BitfieldField(field["name"], field["description"], field["type"], field["bits"])
            if "referenceType" in field:
                newField.referenceType = field["referenceType"]
            if "notes" in field:
                newField.notes = field["notes"]
            newBitfield.addField(newField)
        bitfieldDictionary[bitfield["name"]] = newBitfield
    return bitfieldDictionary

def _processBasicType(zeekFields, zeekField, object, field, type):
    """
    Processes a Parsnip object field and adds information about that field to
    a list of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        zeekField (zeektypes.ZeekField): the ZeekField to initialize and add to
            the zeekFields list.
        object (objects.Object): the object the field being processed belongs
            to.
        field (objects.ObjectField): the ObjectField that is being processed.
        type (str): the Zeek type of the field.
    """
    zeekField.name = utils.commandNameToConst(object.name).lower() + "_" + utils.commandNameToConst(field.name).lower()
    zeekField.type =  type
    zeekFields.append(zeekField)
    object.addIncludedField(field)

def _processCustomType(zeekFields, zeekField, object, field, customFieldTypes):
    """
    Processes a Parsnip object custom type field and adds information about
    that field to a list of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        zeekField (zeektypes.ZeekField): the ZeekField to initialize and add
            to the zeekFields list.
        object (objects.Object): the Object the field being processed belongs
            to.
        field (objects.ObjectField): the ObjectField that is being processed.
        customFieldTypes (set): set of tuples with the key being the
            user-defined custom type name and the tuple consisting of:
                1. the user-defined custom type name,
                2. the conversion function name used to convert the custom type,
                3. the return type of the conversion function.
    """
    _processBasicType(zeekFields, zeekField, object, field, utils.zeekTypeMapping(customFieldTypes[field.type].returnType))

def _processSpicyType(zeekFields, zeekField, object, field):
    """
    Processes a Parsnip Object Spicy type field and adds information about
    that field to a list of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): Array of zeektypes.ZeekField objects to add the
            information to.
        zeekField (zeektypes.ZeekField): The ZeekField to initialize and add
            to the zeekFields.
        object (objects.Object): The object the field being processed belongs
            to.
        field (objects.ObjectField): The ObjectField that is being processed.
    """
    _processBasicType(zeekFields, zeekField, object, field, utils.spicyToZeek[field.type])

def _processSwitchAction(type, action, zeekFields, object, linkingFields, scope, scopes, allObjects, zeekObjects, zeekMainFileObject):
    """
    Processes a Parnsip switch action and adds information about that field to
    a list of fields for the Zeek part of the parser.

    Args:
        type (str): switch type.
        action (switches.SwitchAction): the switch action to process.
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        object (objects.Object): the object the switch action being processed
            belongs to.
        linkingFields (list): array of zeektypes.ZeekField objects
            representing fields that link to other fields.
        scope (str): the non-normalized scope being processed.
        scopes (list): an array of strings with the scope names used within the
            parser.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        zeekObjects (dict): dictionary of Zeek Objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.
    """
    if action.type == "object":
        if type == "link":
            object.addExcludedField(action.name)
    elif action.type in utils.spicyToZeek:
        zeekField = zeektypes.ZeekField()
        zeekField.name = utils.commandNameToConst(object.name).lower() + "_" + utils.commandNameToConst(action.name).lower()
        _processBasicType(zeekFields, zeekField, object, action, utils.spicyToZeek[action.type])
    elif action.type == "list":
        _processListType(zeekFields, action, linkingFields, object, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
    elif action.type == "void":
        pass
    else:
        print("Invalid switch option type: {} in {}".format(action.type, object.name))

def _processSwitchType(zeekFields, linkingFields, object, field, scope, scopes, allObjects, allSwitches, zeekObjects, zeekMainFileObject):
    """
    Processes a Parsnip switch and adds information about that field to a list
    of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        linkingFields (list): array of zeektypes.ZeekField objects
            representing fields that link to other fields.
        object (objects.Object): the object the switch action being processed
            belongs to.
        field (objects.ObjectField): the ObjectField that is being processed.
        scope (str): the non-normalized scope being processed.
        scopes (list): an array of strings with the scope names used within the
            parser.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        allSwitches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.
        zeekObjects (dict): dictionary of Zeek Objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.
    """
    switchType = getSwitchType(field.referenceType, field, scope, scopes, allObjects, allSwitches)
    if switchType == "invalid":
        print("Unknown switch")
        print(field.name)
    elif switchType == "link":
        for switchScope in scopes:
            if field.referenceType in allSwitches[utils.normalizedScope(switchScope, "")]:
                referencedObject = allSwitches[utils.normalizedScope(switchScope, "")][field.referenceType]
                break
        spicyFieldName = referencedObject.dependsOn.name[0].lower() + referencedObject.dependsOn.name[1:] + "LinkID"
        linkObjectField = objects.Link(spicyFieldName, "parentLinkId")
        object.addLinkField(linkObjectField)
        object.needsSpecificExport = True
        for option in referencedObject.options:
            _processSwitchAction("link", option.action, zeekFields, object, linkingFields, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
        if referencedObject.default is not None:
            _processSwitchAction("link", referencedObject.default, zeekFields, object, linkingFields, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
        linkFieldName = utils.commandNameToConst(referencedObject.dependsOn.name).lower() + "_link_id"
        zeekLinkingField = zeektypes.ZeekField(linkFieldName, "string")
        linkingFields.append(zeekLinkingField)
    elif switchType == "contained":
        referencedObject = None
        for switchScope in scopes:
            if field.referenceType in allSwitches[utils.normalizedScope(switchScope, "")]:
                referencedObject = allSwitches[utils.normalizedScope(switchScope, "")][field.referenceType]
                break
        if referencedObject is not None:
            for option in referencedObject.options:
                _processSwitchAction("contained", option.action, zeekFields, object, linkingFields, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
            if referencedObject.default is not None:
                _processSwitchAction("contained", referencedObject.default, zeekFields, object, linkingFields, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
    elif switchType == "trivial":
        # If a trivial switch is in an object that also contains fields, the switch objects should be logged with their parent
        referencedObject = None
        for switchScope in scopes:
            if field.referenceType in allSwitches[utils.normalizedScope(switchScope, "")]:
                referencedObject = allSwitches[utils.normalizedScope(switchScope, "")][field.referenceType]
                break
        if referencedObject is not None:
            for option in referencedObject.options:
                if option.action.type == "object":
                    for objectScope in scopes:
                        if option.action.referenceType in allObjects[utils.normalizedScope(objectScope, "")]:
                            actionObject = allObjects[utils.normalizedScope(objectScope, "")][option.action.referenceType]
                            break
                    if actionObject is not None:
                        actionObject.logWithParent = True

def _processBitsType(zeekFields, object, field, bitfields, scope, generalScope):
    """
    Processes a Parsnip bitfield and adds information about that field to a
    list of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        object (objects.Object): the object the bitfields field being processed
            belongs to.
        field (objects.ObjectField): the ObjectField that is being processed.
        bitfields (dict): dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        scope (str): the non-normalized scope being processed.
        generalScope (str): the default/general scope.
    """
    referenceType = field.referenceType
    fieldZeekName = utils.commandNameToConst(object.name).lower() + "_" +  utils.commandNameToConst(field.name).lower()
    try:
        reference = bitfields[scope][referenceType]
    except KeyError:
        try:
           reference = bitfields[generalScope][referenceType]
        except KeyError:
            print("Unknown bitfield")
            return
    for bitField in reference.fields:
        zeekType = utils.spicyToZeek[bitField.type]
        fieldName = fieldZeekName + "_" + utils.commandNameToConst(bitField.name).lower()
        zeekBitField = zeektypes.ZeekField(fieldName, zeekType)
        zeekFields.append(zeekBitField)
    object.addIncludedField(field)

def _processObjectLink(logStructure, zeekObjects, scope, zeekMainFileObject):
    """
    Gets or adds a zeekObject and record to a Zeek Log structure.

    Args:
        logStructure (str): name of the logging structure (a scope) to add the
            link to.
        zeekObjects (dict): dictionary of Zeek objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        scope (str): The scope the link belongs to.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.

    Returns:
        zeektypes.ZeekRecord: the ZeekRecord that already exsisted or was
        added.
    """
    if logStructure not in zeekObjects[utils.normalizedScope(scope, "object")]:
        zeekObject = zeektypes.ZeekRecord(logStructure, scope)
        zeekObjects[utils.normalizedScope(scope, "object")][logStructure] = zeekObject
        zeekMainFileObject.addRecord(zeekObject)
    else:
        zeekObject = zeekObjects[utils.normalizedScope(scope, "object")][logStructure]
    return zeekObject


def _processLinkingField(referencedObject, linkingFields, zeekObjects, scope, zeekMainFileObject):
    """
    Adds a linking field to the log structure and list of linking fields to
    the zeekObject.

    Args:
        referencedObject (objects.Object): the Object being referenced.
        linkingFields (list): the array of ZeekField objects to add the
            linking field to.
        zeekObjects (dict): dictionary of Zeek objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        scope (str): the scope the link belongs to.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.
    """
    linkFieldName = utils.commandNameToConst(referencedObject.name).lower() + "_link_id"
    zeekLinkingField = zeektypes.ZeekField(linkFieldName, "string")
    linkingFields.append(zeekLinkingField)
    for logStructure in referencedObject.zeekStructure:
        zeekObject = _processObjectLink(logStructure, zeekObjects, scope, zeekMainFileObject)
        zeekObject.addExternalLinkFields(zeekLinkingField)

def _processObjectType(field, linkingFields, object, allObjects, generalScope, scope, scopes, scopedObjects, zeekObjects, zeekMainFileObject):
    """
    Processes a Parsnip object and adds information about that field to a
    list of fields for the Zeek part of the parser.

    Args:
        field (objects.ObjectField): the ObjectField that is being processed.
        linkingFields (list): the array of ZeekField objects to add any
            necessary linking fields to.
        object (objects.Object): the object the bitfields field being processed
            belongs to.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        generalScope (str): the default/general scope.
        scope (str): the non-normalized scope being processed.
        scopes (list): an array of strings with the scope names used within the
            parser.
        scopedObjects (dict): dictionary of all Objects for the parser in the
            scope being processed. the key is the name of the object and the
            value is the Object itself.
        zeekObjects (dict): dictionary of Zeek objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.
    """
    referencedObject = None
    if field.referenceType in allObjects[generalScope]:
        referencedObject = allObjects[generalScope][field.referenceType]
    elif field.referenceType not in scopedObjects:
        print("Referencing out of scope object")
        for objectScope in scopes:
            if field.referenceType in allObjects[utils.normalizedScope(objectScope, "object")]:
                referencedObject = allObjects[utils.normalizedScope(objectScope, "object")][field.referenceType]
                break
        if referencedObject == None:
            print("Unknown Reference: {}".format(field.referenceType))
            return
    else:
        referencedObject = scopedObjects[field.referenceType]
    if referencedObject.logIndependently == True:
        linkingDependency = inputs.Dependency("objectParentLinkId", "string")
        referencedObject.addDependency(linkingDependency)
        spicyFieldName = referencedObject.name[0].lower() + referencedObject.name[1:] + "LinkID"
        linkObjectField = objects.Link(spicyFieldName, "parentLinkId")
        object.addLinkField(linkObjectField)
        linkEndObjectField = objects.Link(spicyFieldName, "parentLinkId", True)
        referencedObject.addLinkField(linkEndObjectField)
        object.addExcludedField(field)
        object.needsSpecificExport = True
        # TODO: Double check this function for side effects
        _processLinkingField(referencedObject, linkingFields, zeekObjects, scope, zeekMainFileObject)

def _processListType(zeekFields, field, linkingFields, object, scope, scopes, allObjects, zeekObjects, zeekMainFileObject):
    """
    Processes a Parsnip list and adds information about that field to a
    list of fields for the Zeek part of the parser.

    Args:
        zeekFields (list): array of zeektypes.ZeekField objects to add the
            information to.
        field (objects.ObjectField): the ObjectField that is being processed.
        linkingFields (list): the array of ZeekField objects to add any
            necessary linking fields to.
        object (objects.Object): the object the bitfields field being processed
            belongs to.
        scope (str): the non-normalized scope being processed.
        scopes (list): an array of strings with the scope names used within the
            parser.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        zeekObjects (dict): dictionary of Zeek objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.
        zeekMainFileObject (zeektypes.ZeekMain): data and functions class
            related to generating main.zeek.
    """
    if field.elementType in utils.spicyToZeek:
        zeekFieldName = utils.commandNameToConst(object.name).lower() + "_" +  utils.commandNameToConst(field.name).lower()
        zeekType = "vector of {}".format(utils.spicyToZeek[field.elementType])
        zeekBitField = zeektypes.ZeekField(zeekFieldName, zeekType)
        object.addIncludedField(field)
        zeekFields.append(zeekBitField)
    elif field.elementType == "object":
        referencedObject, objectScope = utils.getObject(field.referenceType, scopes, allObjects)
        spicyFieldName = referencedObject.name[0].lower() + referencedObject.name[1:] + "LinkID"
        linkObjectField = objects.Link(spicyFieldName, "listParentLinkId")
        object.addLinkField(linkObjectField)
        linkEndObjectField = objects.Link(spicyFieldName, "listParentLinkId", True)
        referencedObject.addLinkField(linkEndObjectField)
        linkInput = inputs.Input("self." + spicyFieldName)
        field.addInput(linkInput)
        linkingDependency = inputs.Dependency("listParentLinkId", "string")
        referencedObject.addDependency(linkingDependency)
        referencedObject.logIndependently == True
        object.addExcludedField(field)
        object.needsSpecificExport = True
        _processLinkingField(referencedObject, linkingFields, zeekObjects, objectScope, zeekMainFileObject)

def _linkScope(scope, zeekObjects):
    """
    Adds linking information between two scopes if necessary.

    Args:
        scope (str): the non-normalized scope being processed.
        zeekObjects (dict): dictionary of Zeek objects for the parser. the
            key is the logging structure that the object belongs to and the
            value is the object itself.

    """
    if scope in utils.scopesHaveCrossScopeLinks:
        zeekMainObject = zeekObjects[utils.normalizedScope(scope, "object")][scope]
        for item in utils.scopesHaveCrossScopeLinks[scope]:
            zeekLinkingField = zeektypes.ZeekField(utils.commandNameToConst(item).lower(), "string")
            zeekMainObject.addExternalLinkFields(zeekLinkingField)

def createZeekObjects(scopes, customFieldTypes, bitfields, allObjects, allSwitches):
    """
    Generates the Zeek objects for the parser.

    Args:
        scopes (list): an array of strings with the scope names used within the
            parser.
        customFieldTypes (set): set of tuples with the key being the
            user-defined custom type name and the tuple consisting of:
                1. the user-defined custom type name,
                2. the conversion function name used to convert the custom type,
                3. and the return type of the conversion function.
        bitfields (dict): dictionary of all Bitfields for the parser broken
            down by scope, followed by the name of the Bitfield.
        allObjects (dict): dictionary of all Objects for the parser broken down
            by scope, followed by the name of the Object.
        allSwitches (dict): dictionary of all Switches for the parser broken
            down by scope, followed by the name of the Switch.


    Returns:
        (dict, zeektypes.ZeekMain): a tuple with the following values:
            1. dictionary of Zeek Objects for the parser. The
            key is the logging structure that the object belongs to and the
            value is the object itself.
            2. data and functions class related to generating main.zeek.
    """
    zeekObjects = {}
    zeekMainFileObject = zeektypes.ZeekMain()
    generalScope = utils.normalizedScope("general", "object")
    for scope in scopes:
        zeekObjects[utils.normalizedScope(scope, "object")] = {}
        # mainZeekRecord = zeektypes.ZeekRecord(scope)
        scopedObjects = allObjects[utils.normalizedScope(scope, "object")]
        for object in scopedObjects.values():
            zeekFields = []
            linkingFields = []
            if len(object.fields) == 1 and object.fields[0].type == "switch":
                switchType = getSwitchType(object.fields[0].referenceType, object.fields[0], scope, scopes, allObjects, allSwitches)
                if switchType == "trivial":
                    object.needsSpecificExport = False
                    continue
            for field in object.fields:
                zeekField = zeektypes.ZeekField()
                if field.type in customFieldTypes:
                    _processCustomType(zeekFields, zeekField, object, field, customFieldTypes)
                elif field.type in utils.spicyToZeek:
                    _processSpicyType(zeekFields, zeekField, object, field)
                elif field.type == "switch":
                    _processSwitchType(zeekFields, linkingFields, object, field, scope, scopes, allObjects, allSwitches, zeekObjects, zeekMainFileObject)
                elif field.type == "bits":
                    _processBitsType(zeekFields, object, field, bitfields, scope, generalScope)
                elif field.type == "object":
                    _processObjectType(field, linkingFields, object, allObjects, generalScope, scope, scopes, scopedObjects, zeekObjects, zeekMainFileObject)
                elif field.type == "list":
                    _processListType(zeekFields, field, linkingFields, object, scope, scopes, allObjects, zeekObjects, zeekMainFileObject)
            for logStructure in object.zeekStructure:
                zeekObject = _processObjectLink(logStructure, zeekObjects, scope, zeekMainFileObject)
                zeekObject.addExternalLinkFieldList(linkingFields)
                zeekObject.addCommandStructure(object)
                zeekObject.addFieldList(zeekFields)
    for scope in scopes:
        _linkScope(scope, zeekObjects)
    return zeekObjects, zeekMainFileObject
