.PHONY: build debug install clean

tool_name = simplelf

build: ${tool_name}.c
	gcc -o ${tool_name} ${tool_name}.c
	gcc -m32 -o ${tool_name}x86 ${tool_name}.c

debug: ${tool_name}.c
	gcc -g3 -o ${tool_name} ${tool_name}.c
	gcc -m32 -g3 -o ${tool_name}x86 ${tool_name}.c

clean:
	rm ${tool_name} ${tool_name}x86 cpoc