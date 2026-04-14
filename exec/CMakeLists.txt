add_executable(exec "main.cpp")

target_link_libraries(exec PRIVATE cl)

set_property(TARGET exec PROPERTY CXX_STANDARD 23)
