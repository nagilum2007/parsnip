# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the SpicyEvent class which represents events for Zeek Spicy
parsers.
"""

import utils

"""
Default arguments for event functions when the protocol sits above TCP or UDP.
"""
DEFAULT_ARGUMENTS = ["$conn", "$is_orig"]

class SpicyEvent:
    """
    This class is used to generate strings representing events in Zeek Spicy
    parsers.

    Settable class variables:
        name: class name that the events are for.
        scope: scope of the class that the events are for.

    Additional class variables:
        arguments: arguments required by the event. value depends on whether
            or not the protcol uses layer 2 or TCP/UDP.
            updated during class initialization.
        eventFields: object fields (used directly) that are to be included
            with the event.
            set during class initialization.
        linkFields: linking fields that are a part of the log, but not part
            of the parser definition.
            set during class initialization.

    ? variables:
        trigger: the trigger keyword to use for the event.
            set to "on" during class initialization.
        relatedBitfields: bitfields related to the event.
    """
    def __new__(cls, *args, **kwargs):
        """
        Constructor

        Returns:
            SpicyEvent: new instance of the class.
        """
        return super().__new__(cls)


    def __init__(self, includedFields=[], linkFields=[]):
        """
        Initialization function

        Args:
            includedFields (list, optional): object fields to use with the
                event. defaults to [].
            linkFields (list, optional): linking fields to use with the
                event. defaults to [].
        """
        self.name = ""
        # TODO: Does not seem to be used anywhere?
        self.trigger = "on"
        self.scope = ""
        if utils.USES_LAYER_2:
            self.arguments = []
        else:
            self.arguments = DEFAULT_ARGUMENTS
        self.eventFields = includedFields
        self.relatedBitfields = {}
        self.linkFields = linkFields

    def generateExport(self):
        """
        Generates the export statement needed for the events file for the
        associated object.

        Returns:
            str: the required export statement for the associated object.
        """
        fullScopeExport = "export {}::{};\n".format(self.scope, self.name)
        return fullScopeExport

    def generateEvent(self, allBitfields):
        """
        Generates the event string for the events file for the associated
        Object.

        Args:
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.

        Returns:
            str: the event string for the associated object.
        """
        basicEvent =  "on {}::{} -> event {}::{}Evt (\n".format(self.scope, self.name, self.scope, self.name)
        scopedArguments = []
        # for link in self.linkFields:
        #     basicEvent += "{}{},\n".format(utils.SINGLE_TAB, link.name)
        for item in self.arguments:
            scopedArguments.append(item)
        for link in self.linkFields:
            #basicEvent += "{}self.{},\n".format(utils.SINGLE_TAB, link.name)
            scopedArguments.append("self.{}".format(link.name))
        if self.eventFields != []:
            for field in self.eventFields:
                if field.type == "bits":
                    referencedBitfield = allBitfields[utils.normalizedScope(field.scope, "bitfield")][field.referenceType]
                    for bitField in referencedBitfield.fields:
                        scopedArguments.append("self.{}.{}".format(field.name, bitField.name))
                    # TODO: What does this line do exactly?
                    self.relatedBitfields[field.name] = self.relatedBitfields
                else:
                    scopedArguments.append("self.{}".format(field.name))
        else:
            scopedArguments.append("self".format(self.scope, self.name))
        for argument in scopedArguments:
            if argument != scopedArguments[-1]:
                basicEvent += "{}{},\n".format(utils.SINGLE_TAB, argument)
            else:
                basicEvent += "{}{}\n);\n\n".format(utils.SINGLE_TAB, argument)
        return basicEvent

    def getEventFunctionName(self, allBitfields):
        """
        Generates the event string for the Zeek scripting file for the
        associated object.

        Args:
            allBitfields (dict): dictionary of all Bitfields for the parser
                broken down by scope, followed by the name of the Bitfield.

        Returns:
            str: the Zeek event string for the associated Object.
        """
        eventName = ""
        if utils.USES_LAYER_2:
            eventName += "event {}::{}Evt (".format(self.scope, self.name)
        else:
            eventName += "event {}::{}Evt (c: connection, is_orig: bool, ".format(self.scope, self.name)
        for link in self.linkFields:
            eventName += "{}: string, ".format(link.name)
        if self.eventFields != []:
            for field in self.eventFields:
                if field.type == "enum":
                    if field.scope != "":
                        eventName += "{}: {}::{}".format(field.name, field.scope, field.referenceType)
                    else:
                        print("Enum field: {} has no scope".format(field.name))
                elif field.type in utils.spicyToZeek:
                    eventName += "{}: {}".format(field.name, utils.spicyToZeek[field.type])
                elif field.type in utils.customFieldTypes:
                    eventName += "{}: {}".format(field.name, utils.zeekTypeMapping(utils.customFieldTypes[field.type].returnType))
                elif field.type == "bits":
                    referencedBitfield = allBitfields[utils.normalizedScope(field.scope, "bitfield")][field.referenceType]
                    for bitField in referencedBitfield.fields:
                        if bitField.type == "enum":
                            if field.scope != "":
                                eventName += "{}: {}::{}".format(bitField.name, bitField.scope, bitField.referenceType)
                            else:
                                print("Enum field: {} has no scope".format(bitField.name))
                        elif bitField.type in utils.spicyToZeek:
                            eventName += "{}: {}".format(bitField.name, utils.spicyToZeek[bitField.type])
                        elif bitField.type in utils.customFieldTypes:
                            eventName += "{}: {},".format(bitField.name, utils.zeekTypeMapping(utils.customFieldTypes[bitField.type].returnType))
                        elif bitField.type == "enum":
                            if field.scope != "":
                                eventName += "{}: {}::{}".format(bitField.name, bitField.scope, bitField.referenceType)
                            else:
                                print("Enum field: {} has no scope".format(bitField.name))
                        else:
                            print("Unknown Bitfield Option: {}".format(field.name))
                        if bitField != referencedBitfield.fields[-1]:
                            eventName += ","
                elif field.type == "object":
                    eventName += "{}: {}::{}".format(field.name,  utils.normalizedScope(field.scope), field.referenceType)
                elif field.type == "list":
                    if field.elementType in utils.spicyToZeek:
                        zeekType = "vector of {}".format(utils.spicyToZeek[field.elementType])
                        eventName += "{}: {}".format(field.name,  zeekType)
                elif "linking" in field.type:
                   continue
                else:
                    print("Unknown {}".format(field.type))
                if field != self.eventFields[-1]:
                    eventName += ", "
        else:
            eventName += "{}: {}::{}".format(self.name.lower(), self.scope, self.name)
        eventName += ") {\n"
        return eventName
