#
# Starting a process on Nocturne: an app of its own (n_app_launch)
#
# multiprocessing/popen_spawn_nocturne.py
#

import io
import os
import nocturne
import _multiprocessing

from .context import reduction, get_spawning_popen, set_spawning_popen
from . import spawn
from . import util

__all__ = ['Popen']


def _stream(fd):
    '''The descriptor if it has a handle to give the child, else -1.'''
    try:
        nocturne._fd_handle(fd)
    except OSError:
        return -1
    return fd


class Popen(object):
    '''
    Start a subprocess to run the code of a process object.

    The child is a new app running Python, which reads the pickled process
    object from a channel. It inherits handles only through the launch's
    table (docs/nocturne-native-abi.md §5): the child's handle i is the
    launcher's self._handles[i]. Handle 0 is the channel's end it reads, 1
    the launcher's app, which reports the launcher's end; duplicate_for_child
    adds the handles the pickled objects name. So the objects are pickled
    before the launch and sent after it.
    '''
    method = 'spawn'

    def __init__(self, process_obj):
        prep_data = spawn.get_preparation_data(process_obj._name)
        self.returncode = None
        reader, writer = _multiprocessing.channel_pair()
        try:
            parent = nocturne._app_open(os.getpid())
            try:
                self._handles = [reader, parent]
                data = io.BytesIO()
                set_spawning_popen(self)
                try:
                    reduction.dump(prep_data, data)
                    reduction.dump(process_obj, data)
                finally:
                    set_spawning_popen(None)
                cmd = spawn.get_command_line(parent_pid=os.getpid(),
                                             pipe_handle=0, parent_handle=1)
                self._handle, self.pid = nocturne._launch(
                    cmd[0], cmd, None, (-1, _stream(1), _stream(2)), None,
                    self._handles)
            finally:
                del self._handles
                nocturne._handle_close(parent)
                nocturne._handle_close(reader)
            self.sentinel = self._handle
            self.finalizer = util.Finalize(self, nocturne._handle_close,
                                           (self._handle,))
            _multiprocessing.channel_send(writer, data.getbuffer())
        finally:
            nocturne._handle_close(writer)

    def duplicate_for_child(self, handle):
        assert self is get_spawning_popen()
        self._handles.append(handle)
        return len(self._handles) - 1

    def wait(self, timeout=None):
        if self.returncode is None:
            end = nocturne._wait(self._handle, timeout)
            if end is not None:
                self.returncode = end.returncode
        return self.returncode

    def poll(self):
        return self.wait(timeout=0)

    def terminate(self):
        '''Stop the app and every app it launched: returncode -SIGTERM.'''
        if self.returncode is not None:
            return
        try:
            nocturne._stop(self._handle)
        except OSError:
            # an app that has already ended cannot be stopped
            if self.poll() is None:
                raise

    kill = terminate

    def close(self):
        self.finalizer()
