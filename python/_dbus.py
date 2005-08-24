
"""Module for high-level communication over the FreeDesktop.org Bus (DBus)

DBus allows you to share and access remote objects between processes
running on the desktop, and also to access system services (such as
the print spool).

To use DBus, first get a Bus object, which provides a connection to one
of a few standard dbus-daemon instances that might be running. From the
Bus you can get a RemoteService. A service is provided by an application or
process connected to the Bus, and represents a set of objects. Once you
have a RemoteService you can get a RemoteObject that implements a specific interface
(an interface is just a standard group of member functions). Then you can call
those member functions directly.

You can think of a complete method call as looking something like:

Bus:SESSION -> Service:org.gnome.Evolution -> Object:/org/gnome/Evolution/Inbox -> Interface: org.gnome.Evolution.MailFolder -> Method: Forward('message1', 'seth@gnome.org')

This communicates over the SESSION Bus to the org.gnome.Evolution process to call the
Forward method of the /org/gnome/Evolution/Inbox object (which provides the
org.gnome.Evolution.MailFolder interface) with two string arguments.

For example, the dbus-daemon itself provides a service and some objects:

# Get a connection to the desktop-wide SESSION bus
bus = dbus.Bus(dbus.Bus.TYPE_SESSION)

# Get the service provided by the dbus-daemon named org.freedesktop.DBus
dbus_service = bus.get_service('org.freedesktop.DBus')

# Get a reference to the desktop bus' standard object, denoted
# by the path /org/freedesktop/DBus. The object /org/freedesktop/DBus
# implements the 'org.freedesktop.DBus' interface
dbus_object = dbus_service.get_object('/org/freedesktop/DBus',
                                       'org.freedesktop.DBus')

# One of the member functions in the org.freedesktop.DBus interface
# is ListServices(), which provides a list of all the other services
# registered on this bus. Call it, and print the list.
print(dbus_object.ListServices())
"""

import dbus

import dbus_bindings

from proxies import *
from exceptions import *
from matchrules import *

class Bus:
    """A connection to a DBus daemon.

    One of three possible standard buses, the SESSION, SYSTEM,
    or STARTER bus
    """
    TYPE_SESSION    = dbus_bindings.BUS_SESSION
    TYPE_SYSTEM     = dbus_bindings.BUS_SYSTEM
    TYPE_STARTER = dbus_bindings.BUS_STARTER

    """bus_type=[Bus.TYPE_SESSION | Bus.TYPE_SYSTEM | Bus.TYPE_STARTER]
    """

    ProxyObjectClass = ProxyObject

    START_REPLY_SUCCESS = dbus_bindings.DBUS_START_REPLY_SUCCESS
    START_REPLY_ALREADY_RUNNING = dbus_bindings.DBUS_START_REPLY_ALREADY_RUNNING 

    def __init__(self, bus_type=TYPE_SESSION, use_default_mainloop=True):
        self._connection = dbus_bindings.bus_get(bus_type)

        self._connection.add_filter(self._signal_func)
        self._match_rule_tree = SignalMatchTree()

        if use_default_mainloop:
            func = getattr(dbus, "_dbus_mainloop_setup_function", None)
            if func != None:
                func(self)

    def get_connection(self):
        return self._connection

    def get_session():
        """Static method that returns the session bus"""
        return SessionBus()

    get_session = staticmethod(get_session)

    def get_system():
        """Static method that returns the system bus"""
        return SystemBus()

    get_system = staticmethod(get_system)


    def get_starter():
        """Static method that returns the starter bus"""
        return StarterBus()

    get_starter = staticmethod(get_starter)


    def get_object(self, named_service, object_path):
        """Get a proxy object to call over the bus"""
        return self.ProxyObjectClass(self, named_service, object_path)

    def _create_args_dict(self, keywords):
        args_dict = None 
        for (key, value) in keywords.iteritems():
            if key.startswith('arg'):
                try:
                    snum = key[3:]
                    num = int(snum)

                    if not args_dict:
                        args_dict = {}

                    args_dict[num] = value
                except ValueError:
                    raise TypeError("Invalid arg index %s"%snum)
            else:
                raise TypeError("Unknown keyword %s"%(key)) 

        return args_dict    

    def add_signal_receiver(self, handler_function, 
                                  signal_name=None,
                                  dbus_interface=None,
                                  named_service=None,
                                  path=None,
                                  **keywords):

        args_dict = self._create_args_dict(keywords)

        if (named_service and named_service[0] != ':'):
            bus_object = self.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
            named_service = bus_object.GetNameOwner(named_service, dbus_interface='org.freedesktop.DBus')
        
        match_rule = SignalMatchRule(signal_name, dbus_interface, named_service, path)

        if args_dict:
            match_rule.add_args_match(args_dict)

        match_rule.add_handler(handler_function)

        self._match_rule_tree.add(match_rule)

        dbus_bindings.bus_add_match(self._connection, repr(match_rule))

    def remove_signal_receiver(self, handler_function, 
                               signal_name=None,
                               dbus_interface=None,
                               named_service=None,
                               path=None,
                               **keywords):

        args_dict = self._create_args_dict(keywords)
    
        if (named_service and named_service[0] != ':'):
            bus_object = self.get_object('org.freedesktop.DBus', '/org/freedesktop/DBus')
            named_service = bus_object.GetNameOwner(named_service, dbus_interface='org.freedesktop.DBus')
        
        match_rule = SignalMatchRule(signal_name, dbus_interface, named_service, path)

        if (args_dict):
            match_rule.add_args_match(args_dict)

        if (handler_function):
            match_rule.add_handler(handler_function)
        
        self._match_rule_tree.remove(match_rule)
        
        #TODO we leak match rules in the lower level bindings.  We need to ref count them

    def get_unix_user(self, named_service):
        """Get the unix user for the given named_service on this Bus"""
        return dbus_bindings.bus_get_unix_user(self._connection, named_service)
    
    def _signal_func(self, connection, message):
        if (message.get_type() != dbus_bindings.MESSAGE_TYPE_SIGNAL):
            return dbus_bindings.HANDLER_RESULT_NOT_YET_HANDLED
        
        dbus_interface      = message.get_interface()
        named_service       = message.get_sender()
        path                = message.get_path()
        signal_name         = message.get_member()

        match_rule = SignalMatchRule(signal_name, dbus_interface, named_service, path)

        self._match_rule_tree.exec_matches(match_rule, message)

    def start_service_by_name(self, named_service):
        return dbus_bindings.bus_start_service_by_name(self._connection, named_service)

class SystemBus(Bus):
    """The system-wide message bus
    """
    def __init__(self):
        Bus.__init__(self, Bus.TYPE_SYSTEM)

class SessionBus(Bus):
    """The session (current login) message bus
    """
    def __init__(self):
        Bus.__init__(self, Bus.TYPE_SESSION)

class StarterBus(Bus):
    """The bus that activated this process (if
    this process was launched by DBus activation)
    """
    def __init__(self):
        Bus.__init__(self, Bus.TYPE_STARTER)

class Interface:
    """An inteface into a remote object

    An Interface can be used to wrap ProxyObjects
    so that calls can be routed to their correct
    dbus interface
    """

    def __init__(self, object, dbus_interface):
        self._obj = object
        self._dbus_interface = dbus_interface

    def connect_to_signal(self, signal_name, handler_function, dbus_interface = None, **keywords):
        if not dbus_interface:
            dbus_interface = self._dbus_interface
            
        self._obj.connect_to_signal(signal_name, handler_function, dbus_interface, **keywords)

    def __getattr__(self, member, **keywords):
        if (keywords.has_key('dbus_interface')):
            _dbus_interface = keywords['dbus_interface']
        else:
            _dbus_interface = self._dbus_interface

        if member == '__call__':
            return object.__call__
        else:
            ret = self._obj.__getattr__(member, dbus_interface=_dbus_interface)
            return ret

    def __repr__(self):
        return '<Interface %r implementing %r at %x>'%(
        self._obj, self._dbus_interface, id(self))
    __str__ = __repr__
