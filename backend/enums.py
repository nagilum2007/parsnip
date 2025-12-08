# Copyright 2024-2025, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Enums and EnumField classes which are data storage and
parser generator helper function classes related to Enum structures.
"""

import utils
from math import ceil

class EnumField:
    """
    This class stores data related to an individual Enum Field. Each field
    represents a value within the Enum. For example, for a Enum named
    Boolean representing boolean values, the two fields could be:
        1. name = "True", loggingValue = "True", value = 1
        2. name = "False", loggingValue = "False", value = 0

    Settable class variables:
        name: field name. this value is used to reference the EnumField when
            referenced by switches and obects.
        loggingValue: human readable value used for parser log output.
        value: the (integer) value that this EnumField represents.
        notes: developer notes.
    """
    # enumFields are different options inside an enumeration
    def __init__(self, name, loggingValue, value):
        """
        Initialization function.

        Args:
            name (str): field name.
            loggingValue (str): value to use when the field is logged.
            value (int): the (integer) value that this field represents.
        """
        self.name = name
        self.loggingValue = loggingValue
        self.value = value
        self.notes = ""

class Enums:
    """
    This class stores data related to an Enum structure.

    Settable class variables:
        name: enum structure name.
        reference: enum structure reference.
            this should be a string providing information of where this
            enum structure definition comes from.
            for example, "Specification Unit A, Section 2.5"
        notes: developer notes.
        size: the size of the enum structure in bits.
            valid values are 8, 16, 32, and 64.
        scope: scope of the enum structure.
        endianness: byte arrangement of the bytes in the enum structure.
            valid values are "big" (default) and "little".

    Additional class variables:
        fields: array of EnumField structures.
            updated using the addField class function.
        column: used for formatting text while generating a parser.
            updated using the addField class function.
        longestField: used for formatting text.
            keeps the length of the longest field name in fields.
            updated using the addField class function.
    """
    def __init__(self, name, reference, size):
        """
        Initialization function.

        Args:
            name (str): enum structure name
            reference (str): enum structure reference.
                this should be a string providing information of where this
                Enum structure definition comes from.
                for example, "Specification Unit A, Section 2.5"
            size (int): the size of the enum structure in bits.
                valid values are 8, 16, 32, and 64.
        """
        self.name = name
        self.reference = reference
        self.notes = ""
        self.size = size
        self.fields = []
        self.column = 0
        self.scope = ""
        self.longestField = 0
        self.endianness = "big"

    def addField(self, field):
        """
        Adds a (non-duplicate) EnumField object to this Enums Object instance.

        If the field item does not currently exist in self.fields, adds the
        field to the array and updates the self.column and self.longestField
        values.

        Args:
            field (EnumField): EnumField object to add to this instance.
        """
        # Adds a field into the enum structure
        for existingField in self.fields:
            if existingField.name == field.name:
                return
        tempColumn = utils.calculateColumn(len(field.name))
        if tempColumn > self.column:
            self.column = tempColumn
        if (len(field.name) > self.longestField):
            self.longestField = len(field.name)
        self.fields.append(field)

    def createSpicyEnumString(self):
        """
        Generates a Zeek Spicy Language definition of this Enums instance using
        the data stored within it.

        Returns:
            str: a string to use within a Spicy parser representing this Enums
                instance.
        """
        # Create spicy-side structures
        if self.reference != "":
            enumString = "# {0}\n".format(self.reference)
        else:
            enumString = ""
        enumString += "public type {0} = enum {{\n".format(self.name)
        for index, field in enumerate(self.fields):
            padding_size = self.column - len(field.name)
            padding = " " * padding_size
            commaString=","
            if index == len(self.fields) - 1:
                commaString = ""
            enumString += "{0}{1}{2}= {3}{4}\n".format(utils.SINGLE_TAB, field.name, padding, field.value, commaString)
        enumString += "};\n"
        return enumString

    def createZeekEnumString(self, enumScope):
        """
        Generates a Zeek Scripting Language definition of this Enums instance
        using the data stored within it.

        Args:
            enumScope (str): scope of the enum in the parser.

        Returns:
            str: a string to use within a Zeek parser representing this enum
                structure instance.
        """
        # This function creates the zeek structure to change an enum into a human readable string
        zeekString = "{}const {} = {{\n".format(utils.SINGLE_TAB, utils.commandNameToConst(self.name).upper())
        scopingValue = "[{}::{}_".format(enumScope, self.name) #Indicates the exported zeek name for zeek-side enums
        for i, field in enumerate(self.fields):
            longestValue = len(scopingValue) + 1 + self.longestField #Scope + longest field + closing ]
            zeekColumn = ceil((longestValue + 1)/4) * 4
            padding_size = zeekColumn - (len(field.name) + len(scopingValue) + 1)
            padding = " " * padding_size
            lineEnd = ","
            if len(self.fields) - 1 == i:
                lineEnd = ""
            zeekString += "{}{}{}]{}= \"{}\"{}\n".format(utils.DOUBLE_TAB, scopingValue, field.name, padding, field.loggingValue, lineEnd)
        zeekString += "{}}}".format(utils.SINGLE_TAB)
        zeekString += " &default=function(i: {}::{}):string".format(enumScope, self.name)
        zeekString += "{return fmt(\"unknown-0x%x\", i); } &redef;\n\n"
        return zeekString
