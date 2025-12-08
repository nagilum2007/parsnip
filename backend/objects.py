# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Object and related classes which are data storage
classes related to Object objects.
"""

import utils
import events
import json_processing

#ADD_DEBUG=True
ADD_DEBUG=False

class Link:
    """
    This class stores data related to a linking field.

    Settable class variables:
        name: name of link, used as the variable name in the parser.
        parameterName: name of the parameter.
        isEndLink: whether or not this link is used to generate an ID.
            if True, the parameter name should be used. if False, then a
            generated ID should be used.
    """
    def __init__(self, name, parameterName, isEndLink = False):
        """
        Initialization function.

        Args:
            name (str): the name of the link. used as the variable name in the
                parser.
            parameterName (str): the value to set the link variable to if
                isEndLink is True.
            isEndLink (bool, optional): True if the variable should be set to
                parameter name, otherwise False if the variable should be a
                generated ID. defaults to False.
        """
        self.name = name
        self.parameterName = parameterName
        self.isEndLink = isEndLink

class ObjectField:
    """
    This class stores data related to an individual Object Field.

    Settable class variables:
        name: field name.
        description: field description.
        notes: developer Notes.
        type: field yype.
        referenceType: name of the of the referenced structure if type is of
            "bits", "enum", "object", "switch", or "list".
        elementType: the type of structure being referenced if type is "list".
        size: the size (in bits) of the field if the associated type requires
            a size.
        until: holds information about a Parsnip "Until" statement related to
            this field if such information exists. otherwise None.
        scope: scope of the referenced type.
        conditional: array of conditional statements related to this field if
            such information exists. otherwise an empty list.
        endianness: the endianness of this field. Must be set to "big" or
            "little".

    Additional class variables:
        inputs: array of Input structures.
            updated using the addInput class function.
    """
    def __init__(self, name, description, type, scope = ""):
        """
        Initialization function.

        Args:
            name (str): field name.
            description (str): field description.
            type (str): field type.
            scope (str, optional): scope containing the field type.
                defaults to "" (default scope).
        """
        self.name = name
        self.description = description
        self.notes = ""
        self.type = type
        self.referenceType = ""
        self.elementType = ""
        self.size = 0
        self.inputs = []
        self.until = None
        self.scope = utils.normalizedScope(scope, type)
        self.conditional = []
        self.endianness = "big"

    def addInput(self, input):
        """
        Adds an Input structure to the internal list of inputs if it does not
        already exist.

        Args:
            input (inputs.Input): the Input structure to add.
        """
        for existingInput in self.inputs:
            if existingInput.equal(input):
                return
        if input not in self.inputs:
            self.inputs.append(input)

    def createSpicyString(self, columns, customTypes, bitfields, switches, enums, dependsOn, fields):
        """
        Generates a Zeek Spicy Langugage definition of this ObjectField
        instance using the data stored within it.

        Args:
            columns (int): the initial column offset for the output string.
            customTypes (dict): the dictionary of any custom types used by the
                parser.
            bitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            switches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            enums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            dependsOn (list): array of variables passed in as dependencies.
            fields (list): array of all fields for the Object this field is
                associated with.

        Returns:
            str: a string to use within a Spicy parser representing this
                ObjectField instance.
        """
        outputString = ""
        if self.notes is not None and "" != self.notes:
            outputString += "# {0}\n{1}".format(self.notes, utils.SINGLE_TAB)
        varString, typeString = utils.determineSpicyStringForType(self.name, self.type, self.elementType, self.referenceType, self.scope, self.size, self.inputs, self.until, columns + 4, customTypes, bitfields, switches, enums)
        conditionalString = ""
        if len(self.conditional) > 0:
            conditionalStringBuilder = self.conditional[:]
            for index in range(len(conditionalStringBuilder)):
                # Get the type and value
                entryType = conditionalStringBuilder[index][0]
                entryValue = conditionalStringBuilder[index][1]
                entryAssociatedValue = None
                if len(conditionalStringBuilder[index]) > 2:
                    entryAssociatedValue = conditionalStringBuilder[index][2]
                if "operator" == entryType and "=" == entryValue:
                    if "=" == entryValue:
                        # conditionalStringBuilder[index][1] = "=="
                        conditionalStringBuilder[index] = (conditionalStringBuilder[index][0], "==")
                elif "indicator" == entryType:
                    # See if we need to handle the value differently:
                    dependsOnIndex = next((index for index, value in enumerate(dependsOn) if value.name == entryValue), -1)
                    if -1 != dependsOnIndex and "enum" == dependsOn[dependsOnIndex].type and entryAssociatedValue is not None:
                        conditionalStringBuilder[entryAssociatedValue] = (conditionalStringBuilder[entryAssociatedValue][0], "{0}::{1}::{2}".format(dependsOn[dependsOnIndex].scope, dependsOn[dependsOnIndex].referenceType, conditionalStringBuilder[entryAssociatedValue][1]))
                    else:
                        fieldsIndex = next((index for index, value in enumerate(fields) if value.name == entryValue), -1)
                        if -1 != fieldsIndex and "enum" == fields[fieldsIndex].type and entryAssociatedValue is not None:
                            conditionalStringBuilder[entryAssociatedValue] = (conditionalStringBuilder[entryAssociatedValue][0], "{0}::{1}::{2}".format(fields[fieldsIndex].scope, fields[fieldsIndex].referenceType, conditionalStringBuilder[entryAssociatedValue][1]))
            for entry in conditionalStringBuilder:
                conditionalString += str(entry[1])
            conditionalString = " if ({0})".format(conditionalString)
        if "little" == self.endianness:
            conditionalString += " &byte-order=spicy::ByteOrder::Little"
        if "switch" == self.type:
            outputString += "{0}{1};".format(typeString, conditionalString)
        elif "linking" == self.type or "endlink" == self.type:
            outputString += "{}".format(typeString)
        else:
            if "" == varString:
                outputString += "{0}{1} : {2}{3};".format(self.name, utils.endingSpace(columns + 4, len(self.name)), typeString, conditionalString)
            else:
                outputString += "var {0}{1} : {2};\n{3}".format(self.name, utils.endingSpace(columns, len(self.name)), varString, utils.SINGLE_TAB)
                outputString += "{0} : {1}{2}".format(utils.endingSpace(columns + 4, 0), typeString, conditionalString)
        return outputString

class Object:
    """
    This class stores data related to an Object.

    Settable class variables:
        name: object name.
        reference: object reference.
            this should be a string providing information of where this Object
            definition comes from.
            for example, "Specification Unit A, Section 2.5.1".
        zeekStructure: array holding logging structure information.
        notes: developer notes.
        scope: the scope of the Object.
        logIndependently: whether or not the Object should be logged
            independently or as part of another structure.
        referenceCount: the number of times this Object is referenced by other
            structures in the parser.
        logWithParent: whether or not the Object should be logged with a parent
            Object.
        needsSpecificExport: whether or not the Object needs a specific export
            statement using the includedFields and excludedFields arrays.

    Additional class variables:
        dependsOn: array of dependencies for the Object.
            updated using the addDependency class function.
        fields: array of ObjectFields for the Object.
            updated using the addField class function.
        column: used for formatting text while generating a parser.
            updated using the addField class function.
        longestField: used for formatting text.
            keeps the length of the longest field name in fields.
            updated using the addField class function.
        linkIds: array of Linking IDs associated with this Object.
            updated using the addLinkField class function.
        excludedFields: array of ObjectField names that should be explicitly
            excluded when importing the Object in other scopes.
            updated using the addExcludedField class function.
        includedFields: array of ObjectField names that should be explicitly
            included when importing the Object in other scopes.
            updated using the addIncludedField class function.
    """
    def __init__(self, name, reference, notes, logIndependently, referenceCount, scope, logWithParent=False):
        """
        Initialization function.

        Args:
            name (str): object name.
            reference (str): object reference.
                this should be a string providing information of where this
                Object definition comes from.
                for example, "Specification Unit A, Section 2.5.1".
            notes (str): developer notes.
            logIndependently (bool): whether or not the Object should be
                logged independently or as part of another structure.
            referenceCount (int): the number of times this Object is
                referenced by other structures in the parser.
            scope (str): the scope of the Object.
            logWithParent (bool, optional): whether or not the Object should
                be logged with a parent structure (Object). defaults to False.
        """
        self.name = name
        self.reference = reference
        self.zeekStructure = []
        self.notes = notes
        self.scope = scope
        self.logIndependently = logIndependently
        self.dependsOn = []
        self.fields = []
        self.referenceCount = referenceCount
        self.column = 0
        self.longestField = 0
        self.logWithParent = logWithParent
        self.linkIds = []
        self.excludedFields = []
        self.includedFields = []
        self.needsSpecificExport = False

    def addField(self, field):
        """
        Adds a (non-duplicate) ObjectField object to this Object instance.

        If the field item does not currently exist in self.fields, adds the
        field to the array and updates the self.column and self.longestField
        values.

        Args:
            field (ObjectField): ObjectField structure to add to this instance.
        """
        if field not in self.fields:
            calculatedColumn = utils.calculateColumn(len(field.name))
            if calculatedColumn > self.column:
                self.column = calculatedColumn
            if (len(field.name) > self.longestField):
                self.longestField = len(field.name)
            self.fields.append(field)

    def addFieldinLocation(self, index, field):
        """
        Adds a (non-duplicate) field in a specific location within the fields
        array.

        Args:
            index (int): the index to insert the field at.
            field (ObjectField): ObjectField structure to add to this instance.
        """
        for existingField in self.fields:
            if field.name == existingField.name:
                return
        self.fields.insert(index, field)

    def removeFieldinLocation(self, idx):
        """
        Removes a field from a specified location within the fields array.
        Raises an IndexError error if the index specified is not valid for the
        array.

        Args:
            idx (int): the index to remove.
        """
        self.fields.pop(idx)

    def addExcludedField(self, fieldName):
        """
        Adds a (non-duplicate) field to the list of fields that should be
        excluded during an import of the Object. The name of the field may not
        already be in either the list of included fields or excluded fields.

        Args:
            fieldName (str): the name of the field to be excluded.
        """
        if fieldName not in self.excludedFields and fieldName not in self.includedFields:
            self.excludedFields.append(fieldName)

    def addIncludedField(self, fieldName):
        """
        Adds a (non-duplicate) field to the list of fields that should be
        explicitly included during an import of the Object and used for
        generating events. The name of the field may not already be in either
        the list of included fields or excluded fields.

        Args:
            fieldName (str): the name of the field to be included.
        """
        if fieldName not in self.excludedFields and fieldName not in self.includedFields:
            self.includedFields.append(fieldName)

    def addDependency(self, dependency):
        """
        Adds a (non-duplicate) dependency to the Object.

        Args:
            dependency (inputs.Dependency): the dependency to add.
        """
        for existingDependency in self.dependsOn:
            if existingDependency.name == dependency.name:
                return
        # TODO: Do we need this if statement after the previous check?
        if dependency not in self.dependsOn:
            self.dependsOn.append(dependency)

    def addLinkField(self, field):
        """
        Adds a (non-duplicate) linking field to the Object.

        Args:
            field (Link): the linking field to add.
        """
        for existingLink in self.linkIds:
            if field.name == existingLink.name:
                return
        self.linkIds.append(field)

    def createSpicyString(self, customTypes, bitfields, switches, enums, isPublic = False):
        """
        Generates a Zeek Spicy Language definition of this Object instance
        using the data stored within it.

        Args:
            customTypes (dict): the dictionary of any custom types used by the
                parser.
            bitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            switches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            enums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            isPublic (bool, optional): whether or not this Object is a "public"
                type Object. in Spicy, public types are types that can be
                called from other modules and Zeek. defaults to False.

        Returns:
            str: a string to use within a Spicy parser representing this
                Object instance.
        """
        outputString = ""
        if self.reference is not None and "" != self.reference:
            outputString += "# {0}\n".format(self.reference)
        if isPublic:
            outputString += "public "
        dependsPart = ""
        if 0 < len(self.dependsOn):
            dependsPart += " ("
            for index, depends in enumerate(self.dependsOn):
                if depends.type == "enum":
                    typeString = "{0}::{1}".format(depends.scope, depends.referenceType)
                else:
                    _, typeString = utils.determineSpicyStringForType(depends.name, depends.type, None, depends.referenceType, depends.scope, depends.size, [], None, self.column, customTypes, bitfields, switches, enums)
                dependsPart += "{0} : {1}".format(depends.name, typeString)
                if index < len(self.dependsOn) - 1:
                    dependsPart += ", "
            dependsPart += ")"
        outputString += "type {0} = unit{1} {{\n".format(self.name, dependsPart)
        if self.linkIds != []:
            varDeclarationString = ""
            initFunctionString = "{}on %init() {{\n".format(utils.SINGLE_TAB)
            for link in self.linkIds:
                varDeclarationString += "{}var {} : string;\n".format(utils.SINGLE_TAB, link.name)
                if link.isEndLink:
                    initFunctionString += "{}self.{} = {};\n".format(utils.DOUBLE_TAB, link.name, link.parameterName)
                else:
                    initFunctionString += "{}self.{} = {}_{}::generateId();\n".format(utils.DOUBLE_TAB, link.name, utils.PROTOCOL_NAME.upper(), utils.ID_SCOPE.upper())
            initFunctionString += "{}}}\n".format(utils.SINGLE_TAB)
            outputString += varDeclarationString
            outputString += initFunctionString
        for field in self.fields:
            outputString += "{0}{1}\n".format(utils.SINGLE_TAB, field.createSpicyString(self.column, customTypes, bitfields, switches, enums, self.dependsOn, self.fields))
        if ADD_DEBUG:
            outputString += "{0}on %done(){{print self;}}\n".format(utils.SINGLE_TAB)
        outputString += "};\n"
        return outputString

    def getEvent(self, moduleName):
        """
        Returns an events.SpicyEvent instance that corresponds to this Object
        instance.

        Args:
            moduleName (str): the scope of this Object instance.

        Returns:
            events.SpicyEvent: the event for this Object instance.
        """
        if self.logWithParent and not self.logIndependently:
            return []
        else:
            if self.needsSpecificExport:
                event = events.SpicyEvent(self.includedFields, self.linkIds)
            else:
                event = events.SpicyEvent()
            event.scope = moduleName
            event.name = self.name
        return event

    def _determineChildOverride(self, specificExportOverride):
        """
        Determines if the child information needs to be overriden or not. The
        value returned is equivalent to
        specificExportOverride || not self.needsSpecificExport.

        Args:
            specificExportOverride (bool): whether to override the regular
                logic used to determine if a override is necessary. True means
                that a override is necessary, otherwise use regular logic.

        Returns:
            bool: True if an override is necessary. otherwise False.
        """
        if specificExportOverride:
            childOverride = True
        else:
            childOverride = not self.needsSpecificExport
        return childOverride

    def _determineProcessingName(self, itemPrefix, specificExportOverride):
        """
        Determine the name to use in an event backend for an Object.

        Args:
            itemPrefix (str): the prefix to use instead of the object name if
                non-empty.
            specificExportOverride (bool): whether to override the regular
                logic used to determine if a override is necessary. True means
                that a override is necessary, otherwise use regular logic.

        Returns:
            str: the name to use for event backend generation for this Object
                instance.
        """
        if itemPrefix == "":
            if self.needsSpecificExport and not specificExportOverride:
                processingName = ""
            else:
                processingName = self.name.lower() + "$"
        else:
            processingName = itemPrefix + "$"
        return processingName

    def _adjustForNonFields(self, moduleName, zeekStructureName, allBitfields, tabSize):
        """
        Generates the event field necessary for creating Zeek logs.

        Args:
            moduleName (str): the scope of this Object instance.
            zeekStructureName (str): name of the Zeek log structure this will
                be logged to.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            tabSize (int): the number of spaces to indent the returned lines
                by.

        Returns:
            (str, str): a tuple with the following values:
                1. the local variable name for the new field.
                2. the code to use for the new field.
        """
        event = self.getEvent(moduleName)
        localVariableName = "info_{}".format(zeekStructureName.lower())
        convertingFunctionString = event.getEventFunctionName(allBitfields)
        if not utils.USES_LAYER_2:
            convertingFunctionString += "{}hook set_session_{}(c);\n\n".format(utils.getTabString(tabSize), zeekStructureName.lower())
            convertingFunctionString += "{}local {} = c${}_{};\n\n".format(utils.getTabString(tabSize), localVariableName, utils.PROTOCOL_NAME.lower(), zeekStructureName.lower())
        else: # utils.USES_LAYER_2:
            convertingFunctionString += "{}local {} = {}($ts=network_time());\n".format(utils.getTabString(tabSize), localVariableName, zeekStructureName)
        return (localVariableName, convertingFunctionString)

    def _finishForNonFields(self, localVariableName, tabSize, zeekStructureName):
        """
        Creates the emit statement for the Zeek logs.

        Args:
            localVariableName (str): the local variable name used for the
                logging field (returned by a call to _adjustForNonFields).
            tabSize (int): the number of spaces to indent the returned lines
                by.
            zeekStructureName (str): name of the Zeek log structure this will
                be logged to.

        Returns:
            str: the emit statement code.
        """
        argument = "c"
        if utils.USES_LAYER_2:
            argument = localVariableName
        convertingFunctionString = "{}{}::emit_{}_{}({});\n".format(utils.getTabString(tabSize), utils.PROTOCOL_NAME.upper(), utils.PROTOCOL_NAME.lower(), zeekStructureName.lower(), argument)
        convertingFunctionString += "}\n"
        return convertingFunctionString

    def _getLinkIDConvertingFunctions(self, tabSize, localVariableName, processingName):
        """
        Creates the logging strings for all link IDs in the object.

        Args:
            tabSize (int): the number of spaces to indent the returned lines
                by.
            localVariableName (str): the local variable name used for the
                logging field (returned by a call to _adjustForNonFields).
            processingName (str): the name to use for event backend generation
                for this Object instance.

        Returns:
            str: the logging assignment strings for all the link IDs in the object.
        """
        convertingFunctionString = ""
        for linkId in self.linkIds:
            convertingFunctionString += "{}{}${} = {}{};\n".format(utils.getTabString(tabSize), localVariableName, utils.commandNameToConst(linkId.name).lower(), processingName, linkId.name)
        return convertingFunctionString

    def _updateOnConditionals(self, startingTabSize, field, specificExportOverride, processingName):
        """
        Adds the starting code to handle conditionals for a field if needed.

        Args:
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            field (ObjectField): the field to process.
            specificExportOverride (bool): whether to override the regular
                logic used to determine if a override is necessary. True means
                that a override is necessary, otherwise use regular logic.
            processingName (str): the name to use for event backend generation
                for this Object instance.

        Returns:
            (int, str): a tuple with the following values:
                1. the new level of indentation to use.
                2. the actual code to use for the conditional statement.
        """
        tabSize = startingTabSize
        convertingFunctionString = ""
        if len(field.conditional) > 0:
            if self.needsSpecificExport and not specificExportOverride:
                pass
            else:
                convertingFunctionString += "{}if ({}?${}){{\n".format(utils.getTabString(tabSize), processingName[:-1], field.name)
                tabSize = startingTabSize + 1
        return (tabSize, convertingFunctionString)

    def _finishOnConditionals(self, field, specificExportOverride, tabSize):
        """
        Adds the finishing code to handle conditionals for a field if needed.

        Args:
            field (ObjectField): the field to process.
            specificExportOverride (bool): whether to override the regular
                logic used to determine if a override is necessary. True means
                that a override is necessary, otherwise use regular logic.
            tabSize (int): the number of spaces to indent the returned lines
                by. this should be the value returned by
                _updateOnConditionals().

        Returns:
            str: the code to use to finish the conditional statement.
        """
        if len(field.conditional) > 0 and (not self.needsSpecificExport or specificExportOverride):
            return "{}}}\n".format(utils.getTabString(tabSize - 1))
        return ""

    def _makeEventBackendForBits(self, field, scopes, allBitfields, allEnums, specificExportOverride, localVariableName, processingName, tabSize):
        """
        Generates and returns a string representing an event backend for a
        Bitfield field.

        Args:
            field (ObjectField): the field to process.
            scopes (list): an array of strings with the scope names used within
                the parser.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            specificExportOverride (bool): whether to override the regular
                logic used to determine if a override is necessary. True means
                that a override is necessary, otherwise use regular logic.
            localVariableName (str): the local variable name used for the
                logging field.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            tabSize (int): the number of spaces to indent the returned lines
                by.

        Returns:
            str: the string representing an event backend for a Bitfield field.
        """
        referenceType = field.referenceType
        fieldPrefix = utils.commandNameToConst(self.name).lower() + "_" +  utils.commandNameToConst(field.name).lower()
        referencedBitfield = None
        for scope in scopes:
            if referenceType in allBitfields[utils.normalizedScope(scope, "bitfield")]:
                referencedBitfield = allBitfields[utils.normalizedScope(scope, "bitfield")][referenceType]
                break
        convertingFunctionString = ""
        if referencedBitfield != None:
            for bitfieldItem in referencedBitfield.fields:
                argument = bitfieldItem.name
                if not self.needsSpecificExport or specificExportOverride:
                    argument = "{}{}${}".format(processingName, field.name, argument)
                convertingFunctionString += "{}{}${}_{} = ".format(utils.getTabString(tabSize), localVariableName, fieldPrefix, utils.commandNameToConst(bitfieldItem.name).lower())
                if bitfieldItem.type == "enum":
                    for scope in scopes:
                        if bitfieldItem.referenceType in allEnums[utils.normalizedScope(scope, "enum")]:
                            enumScope = utils.normalizedScope(scope, "enum")
                            break
                    convertingFunctionString += "{}::{}[{}]".format(enumScope, utils.commandNameToConst(bitfieldItem.referenceType).upper(), argument)
                else:
                    convertingFunctionString += argument
                convertingFunctionString += ";\n"
        return convertingFunctionString

    def _makeEventBackendForEnum(self, field, scopes, allEnums, localVariableName, processingName, tabSize):
        """
        Generates and returns a string representing an event backend for an
        Enum field.

        Args:
            field (ObjectField): the field to process.
            scopes (list): an array of strings with the scope names used within
                the parser.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            localVariableName (str): the local variable name used for the
                logging field.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            tabSize (int): the number of spaces to indent the returned lines
                by.

        Returns:
            str: the string representing an event backend for an Enum field.
        """
        zeekName = utils.commandNameToConst(self.name).lower() + "_" + utils.commandNameToConst(field.name).lower()
        for scope in scopes:
            if field.referenceType in allEnums[utils.normalizedScope(scope, "enum")]:
                enumScope = utils.normalizedScope(scope, "enum")
                break
        return "{}{}${} = {}::{}[{}{}];\n".format(utils.getTabString(tabSize), localVariableName, zeekName, enumScope, utils.commandNameToConst(field.referenceType).upper(), processingName, field.name)

    def _makeEventBackendForList(self, field, processingName, tabSize, localVariableName, includeConditional = False):
        """
        Generates and returns a string representing an event backend for a
        valid list field.

        Args:
            field (ObjectField): the field to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            tabSize (int): the number of spaces to indent the returned lines
                by.
            localVariableName (str): the local variable name used for the
                logging field.
            includeConditional (bool, optional): the list relies on a conditional. defaults to False.

        Returns:
            str|None: if the list is valid, returns a string representing an
                event backend for a List field. otherwise, None.
        """
        convertingFunctionString = ""
        zeekName = utils.commandNameToConst(self.name).lower() + "_" + utils.commandNameToConst(field.name).lower()
        if field.elementType in utils.spicyToZeek:
            actionName = field.name
            if includeConditional:
                if not self.needsSpecificExport or self.logWithParent:
                    argument = "{}?${}".format(processingName[:-1], actionName)
                else:
                    argument = actionName
                convertingFunctionString += "{}if ({}){{\n".format(utils.getTabString(tabSize), argument)
                convertingFunctionString += "{}{}${} = {}{};\n".format(utils.getTabString(tabSize + 1), localVariableName, zeekName, processingName, field.name)
                convertingFunctionString += "{}}}\n".format(utils.getTabString(tabSize))
            else:
               convertingFunctionString += "{}{}${} = {}{};\n".format(utils.getTabString(tabSize), localVariableName, zeekName, processingName, field.name)
            return convertingFunctionString
        if field.elementType == "object":
            return ""
        else:
            print("Invalid List element of type {}".format(field.elementType))

    def _makeEventBackendForObject(self, field, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride):
        """
        Generates and returns a string representing an event backend for an
        Object field.

        Args:
            field (ObjectField): the field to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            moduleName (str): the scope of this Object instance.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            localVariableName (str): the local variable name used for the
                logging field.
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            childOverride (bool): True if the child information needs to be
                overriden. otherwise, False.

        Returns:
            str: the string representing an event backend for an Object field.
        """
        referencedObject = None
        for scope in scopes:
            if field.referenceType in allObjects[utils.normalizedScope(scope, "object")]:
                referencedObject = allObjects[utils.normalizedScope(scope, "object")][field.referenceType]
                break
        if referencedObject != None:
            objectZeekStructureName = processingName + field.name
            return referencedObject.makeEventBackend(moduleName, objectZeekStructureName, allEnums, allBitfields, allObjects, allSwitches, scopes, False, localVariableName, objectZeekStructureName, startingTabSize, childOverride)
        return ""

    def _makeEventBackendForSwitchAction(self, action, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize):
        """
        Generates and returns a string representing an event backend for a
        Switch Action.

        Args:
            action (switches.SwitchAction): the switch action to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            moduleName (str): the scope of this Object instance.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            localVariableName (str): the local variable name used for the
                logging field.
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            childOverride (bool): True if the child information needs to be
                overriden. otherwise, False.
            tabSize (int): the number of spaces per level to indent the
                returned lines by.

        Returns:
            str: the string representing an event backend for a Switch Action.
        """
        convertingFunctionString = ""
        if action.type == "object":
            objectName = action.referenceType
            for scope in scopes:
                if objectName in allObjects[utils.normalizedScope(scope, "")]:
                    object = allObjects[utils.normalizedScope(scope, "")][objectName]
                    argument = action.name
                    if not self.needsSpecificExport or childOverride:
                        argument = "{}?${}".format(processingName[:-1], argument)
                    convertingFunctionString += "{}if ({}){{\n".format(utils.getTabString(tabSize), argument)
                    objectZeekStructureName = processingName + action.name
                    convertingFunctionString += object.makeEventBackend(moduleName, objectZeekStructureName, allEnums, allBitfields, allObjects, allSwitches, scopes, False, localVariableName, objectZeekStructureName, startingTabSize + 1, childOverride)
                    convertingFunctionString += "{}}}\n".format(utils.getTabString(tabSize))
        elif action.type in utils.spicyToZeek:
            argument = action.name
            zeekName = utils.commandNameToConst(self.name).lower() + "_" + utils.commandNameToConst(action.name).lower()
            if not self.needsSpecificExport or childOverride:
                argument = "{}?${}".format(processingName[:-1], argument)
                convertingFunctionString += "{}if ({}){{\n".format(utils.getTabString(tabSize), argument)
                tabSize += 1
            convertingFunctionString += "{}{}${} = {}{};\n".format(utils.getTabString(tabSize), localVariableName, zeekName, processingName, action.name)
            if not self.needsSpecificExport or childOverride:
                tabSize -= 1
                convertingFunctionString += "{}}}\n".format(utils.getTabString(tabSize))
        elif action.type == "list":
            includeConditional = True
            if self.needsSpecificExport and not childOverride:
                includeConditional = False
            convertingFunctionString += self._makeEventBackendForList(action, processingName, tabSize, localVariableName, includeConditional)
        elif action.type == "void":
            pass
        else:
            print("Invalid switch option type: {} in {}".format(action.type, object.name))
        return convertingFunctionString

    def _makeEventBackendForSwitchOptions(self, switch, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize):
        """
        Generates and returns a string representing an event backend for all
        Switch Options in a switch.

        Args:
            switch (switches.Switch): the Switch to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            moduleName (str): the scope of this Object instance.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            localVariableName (str): the local variable name used for the
                logging field.
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            childOverride (bool): True if the child information needs to be
                overriden. otherwise, False.
            tabSize (int): the number of spaces per level to indent the
                returned lines by.

        Returns:
            str: the string representing an event backend for all switch
                options in a switch.
        """
        convertingFunctionString = ""
        for item in switch.options:
            convertingFunctionString += self._makeEventBackendForSwitchAction(item.action, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize)
        return convertingFunctionString

    def _makeEventBackendForSwitchDefault(self, switch, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize):
        """
        Generates and returns a string representing an event backend for a
        Switch default.

        Args:
            switch (switches.Switch): the Switch to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            moduleName (str): the scope of this Object instance.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            localVariableName (str): the local variable name used for the
                logging field.
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            childOverride (bool): True if the child information needs to be
                overriden. otherwise, False.
            tabSize (int): the number of spaces per level to indent the
                returned lines by.

        Returns:
            str: the string representing an event backend for a Switch default.
        """
        return self._makeEventBackendForSwitchAction(switch.default, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize)

    def _makeEventBackendForSwitch(self, field, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize):
        """
        Generates and returns a string representing an event backend for a
        Switch field.

        Args:
            field (ObjectField): the field to process.
            processingName (str): the name to use for event backend generation
                for this Object instance.
            moduleName (str): the scope of this Object instance.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            localVariableName (str): the local variable name used for the
                logging field.
            startingTabSize (int): the number of levels to indent the returned
                lines by.
            childOverride (bool): True if the child information needs to be
                overriden. otherwise, False.
            tabSize (int): the number of spaces per level to indent the returned
                lines by.

        Returns:
            str: the string representing an event backend for a Switch field.
        """
        convertingFunctionString = ""
        for switchScope in scopes:
            if field.referenceType in allSwitches[utils.normalizedScope(switchScope, "")]:
                switch = allSwitches[utils.normalizedScope(switchScope, "")][field.referenceType]
                break
        switchType = ""
        if switch != None:
            switchType = json_processing.getSwitchType(field.referenceType, field, self.scope, scopes, allObjects, allSwitches)
        if switchType == "contained":
            convertingFunctionString = self._makeEventBackendForSwitchOptions(switch, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize)

        if switch.default != None:
            convertingFunctionString += self._makeEventBackendForSwitchDefault(switch, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, startingTabSize, childOverride, tabSize)
        return convertingFunctionString

    def makeEventBackend(self, moduleName, zeekStructureName, allEnums, allBitfields, allObjects, allSwitches, scopes, includeNonFields = True, logObjectVariableName = "", itemPrefix = "", startingTabSize = 1, specificExportOverride=False):
        """
        Generates and returns a string representing an event backend for an
        Object instance.

        Args:
            moduleName (str): the scope of this Object instance.
            zeekStructureName (str): name of the Zeek log structure this will
                be logged to.
            allEnums (dict): dictionary of all Enums for the parser broken down
                by scope, followed by the name of the Enum.
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.
            allObjects (dict): dictionary of all Objects for the parser broken
                down by scope, followed by the name of the Object.
            allSwitches (dict): dictionary of all Switches for the parser broken
                down by scope, followed by the name of the Switch.
            scopes (list): an array of strings with the scope names used within
                the parser.
            includeNonFields (bool, optional): should non-fields (i.e., event
                fields for logs themselves) be added?. defaults to True.
            logObjectVariableName (str, optional): the variable name used for
                the logging field. defaults to "".
            itemPrefix (str, optional): the prefix to use instead of the object
                name if non-empty. defaults to "".
            startingTabSize (int, optional): the number of levels to indent the
                returned lines by. defaults to 1.
            specificExportOverride (bool, optional): whether to override the
                regular logic used to determine if a override is necessary.
                True means that a override is necessary, otherwise use regular
                logic. defaults to False.

        Returns:
            str: event backend for an Object instance.
        """
        convertingFunctionString = ""
        localVariableName = logObjectVariableName
        tabSize = startingTabSize
        childOverride = self._determineChildOverride(specificExportOverride)
        processingName = self._determineProcessingName(itemPrefix, specificExportOverride)
        if includeNonFields:
            localVariableName, convertingFunctionString = self._adjustForNonFields(moduleName, zeekStructureName, allBitfields, tabSize)
        if self.linkIds != []:
            convertingFunctionString += self._getLinkIDConvertingFunctions(tabSize, localVariableName, processingName)
        for field in self.fields:
            if field.type == "switch":
                convertingFunctionString += self._makeEventBackendForSwitch(field, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, tabSize, childOverride, tabSize)
                continue
            tabSize, temp = self._updateOnConditionals(startingTabSize, field, specificExportOverride, processingName)
            convertingFunctionString += temp
            if field.type == "bits":
                convertingFunctionString += self._makeEventBackendForBits(field, scopes, allBitfields, allEnums, specificExportOverride, localVariableName, processingName, tabSize)
            elif field.type == "enum":
                convertingFunctionString += self._makeEventBackendForEnum(field, scopes, allEnums, localVariableName, processingName, tabSize)
            elif field.type == "object":
                convertingFunctionString += self._makeEventBackendForObject(field, processingName, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes, localVariableName, tabSize, childOverride)
            elif field.type == "list":
                convertingFunctionString += self._makeEventBackendForList(field, processingName, tabSize, localVariableName, False)
            else:
                zeekName = utils.commandNameToConst(self.name).lower() + "_" + utils.commandNameToConst(field.name).lower()
                convertingFunctionString += "{}{}${} = {}{};\n".format(utils.getTabString(tabSize), localVariableName, zeekName, processingName, field.name)
            convertingFunctionString += self._finishOnConditionals(field, specificExportOverride, tabSize)
        if includeNonFields:
            convertingFunctionString += self._finishForNonFields(localVariableName, startingTabSize, zeekStructureName)
        return convertingFunctionString

