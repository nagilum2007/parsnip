# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds the Bitfield and Bitfield Field classes which are data
storage classes related to Bitfield objects.
"""

import utils
from math import ceil

class BitfieldField:
    """
    This class stores data related to an individual Bitfield Field.

    Settable class variables:
        name: Field Name.
        description: Field Description.
        notes: Developer Notes.
        type: Field Type (bool, int, enum).
        bits: String representing the bits occupied by the field.
            Two formats allowed: "single_bit", "lower_bit..upper_bit".
            Example: "3" and "2..7".
        referenceType: Enum Object name (if type is of enum).
            Used for conversion to a more human-readable value in the parser.
        scope: Scope of the reference type.
    """
    def __init__(self, name, description, fieldType, bits, scope = ""):
        """
        Initialization Function

        Args:
            name (str): Field Name
            description (str): Field Description
            fieldType (str): Field Type string
            bits (str): The bit(s) this field occupies.
                Format "bit" or "lower..upper" (i.e., "3" or "2..7")
            scope (str, optional): Scope containing the field type.
                Defaults to "" (default scope).
        """
        self.name = name
        self.description = description
        self.notes = ""
        self.type = fieldType
        self.bits = bits
        self.referenceType = ""
        self.scope = utils.normalizedScope(scope, fieldType)

class Bitfield:
    """
    This class stores data related to a Bitfield object.

    Settable class variables:
        name: Bitfield Object Name.
        reference: Bitfield Object Reference.
                This should be a string providing information of where this
                Bitfield Object definition comes from.
                For example, "Specification Unit A, Section 2.5"
        notes: Developer Notes.
        size: The size of the Bitfield Object in bits.
                Valid values are 8, 16, 32, and 64.
        scope: Scope of the Bitfield Object.
        endianness: Byte arrangement of the bytes in the Bitfield Object.
            Valid values are "big" (default) and "little".

    Additional class variables:
        fields: Array of BitfieldField objects.
            Updated using the addField class function.
        column: Used for formatting text while generating a parser.
            Updated using the addField class function.
        longestField: Used for formatting text.
            Keeps the length of the longest field name in fields.
            Updated using the addField class function.
    """
    def __init__(self, name, reference, notes, size):
        """
        Initialization Function

        Args:
            name (str): Bitfield Object Name
            reference (str): Bitfield Object Reference.
                This should be a string providing information of where this
                Bitfield Object definition comes from.
                For example, "Specification Unit A, Section 2.5"
            notes (str): User defined notes.
            size (int): The size of the Bitfield Object in bits.
                Valid values are 8, 16, 32, and 64.
        """
        self.name = name
        self.reference = reference
        self.notes = notes
        self.size = size
        self.fields = []
        self.column = 0
        self.scope = ""
        self.longestField = 0
        self.endianness = "big"

    def addField(self, field):
        """
        Adds a (non-duplicate) BitfieldField object to this Bitfield Object
        instance.

        If the field item does not currently exist in self.fields, adds the
        field to the array and updates the self.column and self.longestField
        values.

        Args:
            field (BitfieldField): BitfieldField object to add to this instance.
        """
        for existingField in self.fields:
            if existingField.name == field.name:
                return
        if (ceil((len(field.name) + 1)/4) * 4) > self.column:
            self.column = (ceil((len(field.name) + 1)/4) * 4)
        if (len(field.name) > self.longestField):
            self.longestField = len(field.name)
        self.fields.append(field)

