"""sentinel-edge: in-path enforcement gateway.

Sits between the ESP fleet and the backend: pulls oracle-verified filters over
OTA, compiles them to a native shared object, loads them with ctypes, and drops
matching frames in the traffic path before they reach the backend. The backend
is the brain (detect + agent + oracle + publish); this is the muscle.
"""
