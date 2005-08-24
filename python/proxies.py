import dbus_bindings
from exceptions import MissingReplyHandlerException, MissingErrorHandlerException

class DeferedMethod:
    """A DeferedMethod
    
    This is returned instead of ProxyMethod when we are defering DBus calls
    while waiting for introspection data to be returned
    
    This class can be used for debugging purposes
    """
    def __call__(self, *args, **keywords):
        return None

class ProxyMethod:
    """A proxy Method.

    Typically a member of a ProxyObject. Calls to the
    method produce messages that travel over the Bus and are routed
    to a specific named Service.
    """
    def __init__(self, connection, named_service, object_path, dbus_interface, method_name):
        self._connection   = connection
        self._named_service = named_service
        self._object_path  = object_path
        self._method_name  = method_name
        self._dbus_interface = dbus_interface

    def __call__(self, *args, **keywords):
        dbus_interface = self._dbus_interface
        if keywords.has_key('dbus_interface'):
            dbus_interface = keywords['dbus_interface']

        timeout = -1
        if keywords.has_key('timeout'):
            timeout = keywords['timeout']

        reply_handler = None
        if keywords.has_key('reply_handler'):
            reply_handler = keywords['reply_handler']

        error_handler = None
        if keywords.has_key('error_handler'):
            error_handler = keywords['error_handler']            

        if not(reply_handler and error_handler):
            if reply_handler:
                raise MissingErrorHandlerException()
            elif error_handler:
                raise MissingReplyHandlerException()

        message = dbus_bindings.MethodCall(self._object_path, dbus_interface, self._method_name)
        message.set_destination(self._named_service)
        
        # Add the arguments to the function
        iter = message.get_iter(True)
        for arg in args:
            iter.append(arg)

        if reply_handler:
            result = self._connection.send_with_reply_handlers(message, timeout, reply_handler, error_handler)
            args_tuple = result
        else:
            reply_message = self._connection.send_with_reply_and_block(message, timeout)
            args_tuple = reply_message.get_args_list()
            
        if len(args_tuple) == 0:
            return
        elif len(args_tuple) == 1:
            return args_tuple[0]
        else:
            return args_tuple


class ProxyObject:
    """A proxy to the remote Object.

    A ProxyObject is provided by the Bus. ProxyObjects
    have member functions, and can be called like normal Python objects.
    """
    ProxyMethodClass = ProxyMethod
    DeferedMethodClass = DeferedMethod

    INTROSPECT_STATE_DONT_INTROSPECT = 0
    INTROSPECT_STATE_INTROSPECT_IN_PROGRESS = 1
    INTROSPECT_STATE_INTROSPECT_DONE = 2

    #TODO: default introspect to False right now because it is not done yet
    #      make sure to default to True later
    def __init__(self, bus, named_service, object_path, introspect=False):
        self._bus           = bus
        self._named_service = named_service
        self._object_path   = object_path
        
        #PendingCall object for Introspect call
        self._pending_introspect = None
        #queue of async calls waiting on the Introspect to return 
        self._pending_introspect_queue = []
 
        if not introspect:
            self._introspect_state = self.INTROSPECT_STATE_DONT_INTROSPECT
        else:
            self._introspect_state = self.INTROSPECT_STATE_INTROSPECT_IN_PROGRESS
            
            (result, self._pending_introspect) = self._Introspect()
            

    def connect_to_signal(self, signal_name, handler_function, dbus_interface=None, **keywords):
        self._bus.add_signal_receiver(handler_function,
                                      signal_name=signal_name,
                                      dbus_interface=dbus_interface,
                                      named_service=self._named_service,
                                      path=self._object_path,
                                      **keywords)

    def _Introspect(self):
        message = dbus_bindings.MethodCall(self._object_path, 'org.freedesktop.DBus.Introspectable', 'Introspect')
        message.set_destination(self._named_service)
        
        result = self._bus.get_connection().send_with_reply_handlers(message, -1, 
                                                                                           self._introspect_reply_handler, 
                                                                                           self._introspect_error_handler)
        return result   
            
    def _introspect_reply_handler(self, data):
        self._introspect_state = self.INTROSPECT_STATE_INTROSPECT_DONE
        
        for call in self._pending_introspect_queue:
            (member, iface, args, keywords) = call
            call_object = self.ProxyMethodClass(self._bus.get_connection(),
                                                                       self._named_service,
                                                                       self._object_path, iface, member)
                                                                       
            call_object(args, keywords)

    def _introspect_error_handler(self, error):
        self._introspect_state = self.INTROSPECT_STATE_DONT_INTROSPECT

    def __getattr__(self, member, **keywords):
        if member == '__call__':
            return object.__call__
        elif member.startswith('__') and member.endswith('__'):
            raise AttributeError(member)
        else:
            iface = None
            if keywords.has_key('dbus_interface'):
                iface = keywords['dbus_interface']

            if self._introspect_state == self.INTROSPECT_STATE_INTROSPECT_IN_PROGRESS:
                reply_handler = None
                if keywords.has_key('reply_handler'):
                    reply_handler = keywords['reply_handler']

                error_handler = None
                if keywords.has_key('error_handler'):
                    error_handler = keywords['error_handler']

                if not reply_handler:
                    self._pending_introspect.block()
                else:
                    call = (memeber, iface, args, keywords)
                    self._pending_introspect_queue.append(call)
                    
                    ret = self.DeferedMethodClass()
                    return ret
                   
            ret = self.ProxyMethodClass(self._bus.get_connection(),
                                self._named_service,
                                self._object_path, iface, member)
            return ret

    def __repr__(self):
        return '<ProxyObject wrapping %s %s %s at %x>'%( 
            self._bus, self._named_service, self._object_path , id(self))
    __str__ = __repr__

