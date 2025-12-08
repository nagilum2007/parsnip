# Copyright 2024, Battelle Energy Alliance, LLC, ALL RIGHTS RESERVED

"""
This module holds functions and variables related to Zeek code.
"""

from string import Template
from math import ceil
import re
import utils
import generation_utils

# This doesn't seem to be used?
TYPE_TO_EMPTY  = {
    "string" : "",
    "count" : 0,
}

# This doesn't seem to be used?
genericZeekField = Template("""
    # Timestamp for when the event happened.
    ts$padding: time &log;

    # Unique ID for the connection.
    uid$padding: string &log;

    # The connection's 4-tuple of endpoint addresses/ports.
    id$padding: conn_id &log;
    """)


class ZeekField:
    """
    This class stores data related to a Zeek field.

    Settable class variables:
        name: name of the field.
        type: the type of the field.
    """
    def __init__(self, name="", type=""):
        """
        Initialization function.

        Args:
            name (str, optional): the name of the field. defaults to "".
            type (str, optional): the type of the field. defaults to "".
        """
        self.name = name
        self.type = type


class ZeekMain:
    """
    This class holds data and has functions related to generating main.zeek.

    Additional class variables:
        records: array of ZeekRecord items to be used with this instance.
            updated using the addRecord class function.
    """
    def __init__(self):
        """
        Initialization function.
        """
        self.records = []

    def addRecord(self, record):
        """
        Adds a (non-duplicate) ZeekRecord to this instance of the class.

        Args:
            record (ZeekRecord): the record to add.
        """
        for currentRecord in self.records:
            if record.name == currentRecord.name:
                return
        self.records.append(record)

    def _generateLogStreamIndividualString(self, record, indent, isSingle):
        """
        Generates Zeek code to create a log stream for a particular record.

        Args:
            record (ZeekRecord): the record to create the log stream for.
            indent (str): the indentation string to prepend to the lines.
            isSingle (bool): whether or not there is only one record associated
                with this log stream.

        Returns:
            str: the Zeek code for generating a log stream for the record.
        """
        returnString = ""
        pathName = record.name.lower()
        if not isSingle:
            pathName = pathName.replace("_log", "")
        recordLogName = "LOG_{}".format(record.name.upper())
        returnString += "{}Log::create_stream({}::{},\n".format(indent, utils.PROTOCOL_NAME.upper(), recordLogName)
        returnString += "{}[$columns={}{},\n".format(indent, record.scope, record.name)
        returnString += "{}$ev=log_{},\n".format(indent, record.name.lower())
        # If the record is named "general", don't append the name to the path
        if pathName == "general":
            returnString += "{}$path=\"{}\",\n".format(indent, utils.PROTOCOL_NAME.lower())
        else:
            returnString += "{}$path=\"{}_{}\",\n".format(indent, utils.PROTOCOL_NAME.lower(), pathName)
        #returnString += "{}$path=\"{}_{}\",\n".format(indent, utils.PROTOCOL_NAME.lower(), pathName)
        returnString += "{}$policy=log_policy_{}]);\n".format(indent, record.name.lower())
        return returnString

    def _generateLogStreamString(self, records):
        """
        Generates Zeek code to create a log stream for all records in this
        instance of the class.

        Args:
            records (list): array of ZeekRecord items to create the log streams
                for.

        Returns:
            str: the Zeek code for generating the log streams.
        """
        returnString = ""
        if len(records) > 1:
            for record in self.records:
                returnString += self._generateLogStreamIndividualString(record, utils.SINGLE_TAB, False)
        else:
            returnString += self._generateLogStreamIndividualString(self.records[0], " " * 22, True)
        return returnString

    def _generateFileString(self, records):
        """
        Generates Zeek code to create the exports for the logs.

        Args:
            records (list): array of ZeekRecord items to create the exports
                for.

        Returns:
            str: the Zeek code to generate the exports for the logs.
        """
        returnString = utils.SINGLE_TAB + "redef enum Log::ID += {"
        if len(records) > 1:
            returnString += "\n"
            for record in records:
                recordLogName = "LOG_{}".format(record.name.upper())
                returnString += "{}{}".format(" " * 28, recordLogName)
                if record != self.records[len(self.records) - 1]:
                    returnString += ","
                returnString += "\n"
            returnString += (" " * 27)
        else:
            recordLogName = "LOG_{}".format(records[0].name.upper())
            returnString += " {} ".format(recordLogName)
        returnString += "};\n\n"
        return returnString

    def _generateGlobals(self, records):
        """
        Generates Zeek code to allow logs to be enabled or disabled.

        Args:
            records (list): array of ZeekRecord items to create the exports
                for.

        Returns:
            str: the Zeek code to generate the exports to allow logging to be
                enabled or disabled.
        """
        returnString = ""
        for record in records:
            recordLogEventName = "log_{}".format(record.name.lower())
            recordLogPolicyName = "log_policy_{}".format(record.name.lower())
            returnString += "{}global {}: event(rec: {}{});\n".format(utils.SINGLE_TAB, recordLogEventName, record.scope, record.name)
            returnString += "{}global {}: Log::PolicyHook;\n".format(utils.SINGLE_TAB, recordLogPolicyName)
        return returnString

    def _generateEmits(self, records):
        """
        Generates Zeek code to emit the logs (i.e., allow the logs to be
        generated).

        Args:
            records (list): array of ZeekRecord items to create the exports
                for.

        Returns:
            str: the Zeek code to allow the logs to be written to.
        """
        returnString = ""
        for record in records:
            recordLogEventName = "log_{}".format(record.name.lower())
            returnString += "{}global emit_{}_{}: function(".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.lower(), record.name.lower())
            if utils.USES_LAYER_2:
                if record.scope != "":
                    returnString += "{}_record: {}::{}".format(record.name.lower(), record.scope, record.name)
                else:
                    returnString += "{}_record: {}".format(record.name.lower(), record.name)
            else:
                returnString += "c: connection"
            returnString += ");\n"
        return returnString

    def _generateConnections(self, records):
        """
        Generates the Zeek code to add the records to the record connection
        value used by Zeek.

        Args:
            records (list): array of ZeekRecord items to create the exports
                for.

        Returns:
            str: the Zeek code to add the records.
        """
        returnString = ""
        returnString += "# redefine connection record to contain one of each of the {} records\n".format(utils.PROTOCOL_NAME.lower())
        returnString += "redef record connection += {\n"
        for record in records:
            returnString += "{}{}_{}: {}{} &optional;\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.lower(), record.name.lower(), record.scope, record.name)
        returnString += "};\n\n"
        return returnString

    def generateMainFile(self, usesLayer2, configuration):
        """
        Generates the majority of Zeek code to be placed in main.zeek.

        Args:
            usesLayer2 (bool): whether or not the parser works over Layer 2
                instead of TCP or UDP.
            configuration (Config): parser configuration information.

        Returns:
            str: the contents of the main.zeek file.
        """
        fileString = "export {\n"
        fileString += self._generateFileString(self.records)
        fileString += self._generateGlobals(self.records)
        fileString += self._generateEmits(self.records)
        fileString += "\n}\n\n"

        fileString += self._generateConnections(self.records)

        analyzerString = ""
        if [] != configuration.ports:
            tempPorts = {}
            for port in configuration.ports:
                protocol = port.get("protocol").lower()
                if protocol not in tempPorts:
                    tempPorts[protocol] = []
                tempPorts[protocol].append(port.get("port"))
            for key in tempPorts:
                fileString += "# Define {0} ports\n".format(key)
                fileString += "const {0}_ports = {{\n".format(key)
                for value in tempPorts[key]:
                    fileString += "{0}{1}/{2},\n".format(utils.SINGLE_TAB, value, key)
                fileString += "};\n\n"
                analyzerString += "{0}Analyzer::register_for_ports(Analyzer::ANALYZER_SPICY_{1}, {2});\n".format(utils.SINGLE_TAB, "{0}_{1}".format(utils.PROTOCOL_NAME.upper(), key.upper()), "{0}_ports".format(key))
        fileString += "# Initialization Function\n"
        fileString += "event zeek_init() &priority=5 {\n"
        # Handle ethernet registration if necessary
        if usesLayer2:
            fileString += "{0}# Register on top of Ethernet\n".format(utils.SINGLE_TAB)
            fileString += "{0}if ( ! PacketAnalyzer::try_register_packet_analyzer_by_name(\"Ethernet\", {1}, \"spicy_{2}\") )\n".format(utils.SINGLE_TAB, configuration.ethernetProtocolNumber, utils.PROTOCOL_NAME.upper())
            fileString += "{0}Reporter::error(\"cannot register Spicy analyzer\");".format(utils.DOUBLE_TAB)
            fileString += "\n"
        fileString += "{}# initialize logging streams for all {} logs\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.lower())
        fileString += self._generateLogStreamString(self.records)
        fileString += analyzerString
        fileString += "}\n"
        return fileString

    def addLoggingFunction(self):
        """
        Generates the Zeek code to write the to the logging portion of
        main.zeek.

        Returns:
            str: the Zeek code to use for the logging functions portion of
                main.zeek.
        """
        functionsString = ""
        for record in self.records:
            connectionName = "{}_{}".format(utils.PROTOCOL_NAME.lower(), record.name.lower())
            if utils.USES_LAYER_2:
                if record.scope != "":
                    recordScope = "{}_{}::".format(utils.PROTOCOL_NAME.upper(), record.name.upper())
                    fileString += "{}global emit_{}_{}: function({}_record: {}::{});\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.lower(), record.name.lower(), recordScope, record.name.lower())
                else:
                    functionsString += "function emit_{}_{}({}_record: {}) {{\n".format(utils.PROTOCOL_NAME.lower(), record.name.lower(), record.name.lower(), record.name)
                functionsString += "{}Log::write({}::LOG_{}, {}_record);\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.upper(), record.name.upper(), record.name.lower())
            else:
                functionsString += "function emit_{}_{}(c: connection) {{\n".format(utils.PROTOCOL_NAME.lower(), record.name.lower())
                functionsString += "{}if (! c?${} )\n".format(utils.SINGLE_TAB, connectionName)
                functionsString += "{}return;\n".format(utils.DOUBLE_TAB)
                functionsString += "{}Log::write({}::LOG_{}, c${});\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.upper(), record.name.upper(), connectionName)
                functionsString += "{}delete c${};\n".format(utils.SINGLE_TAB, connectionName)
            functionsString += "}\n\n"
        return functionsString

class ZeekRecord:
    """
    This class stores data related to an individual Zeek Record.

    Non-settable class variables:
        defaultRecords:
            updated using the __init__ class function.
        fields:
            updated using the addField or addFieldList class functions.
        commandStructures:
            updated using the addCommandStructure class function.
        column:
            updated using the addExternalLinkFields, addExternalLinkFieldList,
            addField, or addFieldList class functions.
        name:
            updated using the __init__ class function.
        scope:
            update using the __init__ class function.
        externalLinkFields:
            updated using the addExternalLinkFields or addExternalLinkFieldList
            class functions.

    ??? class variables:
        logName
        protocol
    """
    def initializeRecordFields(self):
        """
        Generates the list of default record fields for the record.

        Returns:
            list: array of ZeekField items that are the default fields for the
                record.
        """
        protocolField = ZeekField()
        protocolField.name = "proto"
        protocolField.type = "transport_proto"
        timestampField = ZeekField()
        timestampField.name = "ts"
        timestampField.type = "time"
        if utils.USES_LAYER_2:
            commonFields = [timestampField]
        else:
            uidField = ZeekField()
            uidField.name = "uid"
            uidField.type = "string"
            idField = ZeekField()
            idField.name = "id"
            idField.type = "conn_id"
            commonFields = [timestampField, uidField, idField, protocolField]
        return commonFields

    def __init__(self, name, scope = ""):
        """
        Initialization function.

        Args:
            name (str): name of the record.
            scope (str, optional): the scope of the record. defaults to "".
        """
        self.defaultRecords = self.initializeRecordFields()
        self.fields = []
        self.commandStructures = []
        self.column = 8
        #self.name = utils.commandNameToConst(name).lower() + "_log" -> removed extra "_log" from output log filename
        self.name = utils.commandNameToConst(name).lower()

        # self.subname = ""
        # TODO: Is this used anywhere?
        self.logName = ""
        # TODO: Is this used anywhere?
        self.protocol = ""
        if scope == "":
            scopeName = self.name
        else:
            scopeName = scope
        if scopeName != "general":
            self.scope = "{}_{}::".format(utils.PROTOCOL_NAME.upper(), scopeName.upper())
        else:
            self.scope = ""
        self.externalLinkFields = []

    def addExternalLinkFields(self, field):
        """
        Adds a (non-duplicate) ZeekField to the list of external link fields.

        Args:
            field (ZeekField): the field to add.
        """
        for existingField in self.externalLinkFields:
            if existingField.name == field.name:
                return
        if (ceil((len(field.name) + 1)/4) * 4) > self.column:
            self.column = (ceil((len(field.name) + 1)/4) * 4)
        self.externalLinkFields.append(field)

    def addExternalLinkFieldList(self, fieldList):
        """
        Adds ZeekField (non-duplicate) items from a list to the list of
        external link fields.

        Args:
            fieldList (list): array of ZeekField items to add.
        """
        for field in fieldList:
            for existingField in self.externalLinkFields:
                if existingField.name == field.name:
                    break
            else:
                if (ceil((len(field.name) + 1)/4) * 4) > self.column:
                    self.column = (ceil((len(field.name) + 1)/4) * 4)
                self.externalLinkFields.append(field)

    def addField(self, field):
        """
        Adds a (non-duplicate) field to the list of fields in the record.

        Args:
            field (ZeekField): the ZeekField instance to add.
        """
        for existingField in self.fields:
            if existingField.name == field.name:
                return
        if (ceil((len(field.name) + 1)/4) * 4) > self.column:
            self.column = (ceil((len(field.name) + 1)/4) * 4)
        self.fields.append(field)

    def addFieldList(self, fieldList):
        """
        Adds ZeekField (non-duplicate) items from a list to the list of fields
        in the record.

        Args:
            fieldList (list): array of ZeekField items to add.
        """
        for field in fieldList:
            for existingField in self.fields:
                if existingField.name == field.name:
                    break
            else:
                if (ceil((len(field.name) + 1)/4) * 4) > self.column:
                    self.column = (ceil((len(field.name) + 1)/4) * 4)
                self.fields.append(field)

    def addHook(self):
        """
        Generates the Zeek code to add a hook for the Zeek record.

        Returns:
            str: the Zeek code for this record.
        """
        #TODO: Handle header information; Maybe add additional initial formatting
        hookString = ""
        if not utils.USES_LAYER_2:
            hookString = "hook set_session_{}(c: connection) {{\n".format(self.name.lower())
            hookString += "{}if ( ! c?${}_{} )\n".format(utils.SINGLE_TAB, utils.PROTOCOL_NAME.lower(), self.name.lower())
            hookString += "{}c${}_{} = {}(\n".format(utils.DOUBLE_TAB, utils.PROTOCOL_NAME.lower(), self.name.lower(), self.name)
            hookString += "{}$ts=network_time(),\n".format(utils.SINGLE_TAB * 3)
            hookString += "{}$uid=c$uid,\n".format(utils.SINGLE_TAB * 3)
            hookString += "{}$id=c$id,\n".format(utils.SINGLE_TAB * 3)
            hookString += "{}$proto=get_conn_transport_proto(c$id));\n".format(utils.SINGLE_TAB * 3)
            hookString += "}\n\n"
        return hookString

    def addCommandStructure(self, commandStructure):
        """
        Adds a (non-duplicate) Object if necessary to the record.

        Args:
            commandStructure (objects.Object): the object to add.
        """
        if commandStructure not in self.commandStructures and (commandStructure.logIndependently or not commandStructure.logWithParent):
            self.commandStructures.append(commandStructure)

    def addFunctions(self, moduleName, allEnums, allBitfields, allObjects, allSwitches, scopes):
        """
        Generates the Zeek code for events for the Objects associated with this
        record.

        Args:
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

        Returns:
            str: the Zeek code for the event backends.
        """
        functionString = ""
        for command in self.commandStructures:
            functionString += command.makeEventBackend(moduleName, self.name, allEnums, allBitfields, allObjects, allSwitches, scopes)
        return functionString

    def createRecord(self):
        """
        Generates the Zeek code for this record.

        Returns:
            str: the Zeek code for this record.
        """
        recordString = ""
        recordString += "{}type {}: record {{\n".format(utils.SINGLE_TAB, self.name)
        for field in self.defaultRecords:
            paddingSize = (self.column - len(field.name))
            padding = paddingSize * ' '
            recordString += "{}{}{}: {} &log;\n".format(utils.DOUBLE_TAB, field.name, padding, field.type)
        for field in self.externalLinkFields:
            paddingSize = (self.column - len(field.name))
            padding = paddingSize * ' '
            recordString += "{}{}{}: {} &log &optional;\n".format(utils.DOUBLE_TAB, field.name, padding, field.type)
        for field in self.fields:
            paddingSize = (self.column - len(field.name))
            padding = paddingSize * ' '
            recordString += "{}{}{}: {} &log &optional;\n".format(utils.DOUBLE_TAB, field.name, padding, field.type)
        recordString += "{}}};\n\n".format(utils.SINGLE_TAB)
        return recordString
