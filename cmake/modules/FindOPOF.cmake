# Find the native Openoffload and dependent gRPC libraries
#
#  OPOF_LIBRARIES   - List of libraries when using openoffload .
#  OPOF_FOUND       - True if OPOF found.


IF(NOT OPOF_FOUND)


message(STATUS "BDF OPOF LIBRARIES: " ${OPOF_LIBRARIES})

MARK_AS_ADVANCED( OPOF_LIBRARIES )
ENDIF(NOT OPOF_FOUND)
