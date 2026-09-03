function()
if(MSVC)
        target_compile_options(${target} PRIVATE  /W4 /permissive- /wd4324)
else()
        target_compile_options(${target} PRIVATE
        -Wall -Wextra -Wpedantic 
        -Wconversoin -Wsign_conversion -Wshadow
        Wno_unused_parameter)
endif()
endfunction()
