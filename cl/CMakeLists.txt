file(GLOB_RECURSE CL_SOURCES CONFIGURE_DEPENDS "src/*.cpp")

add_library(cl STATIC ${CL_SOURCES})

target_include_directories(cl
    PUBLIC  "include"
    PRIVATE "src"
)

set_property(TARGET cl PROPERTY CXX_STANDARD 23)
