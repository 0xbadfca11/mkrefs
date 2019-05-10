CXX = clang-cl
CXXFLAGS += -utf-8 -std:c++latest -EHsc -GR- -W4 -Werror=gnu -Wmicrosoft -Wno-missing-field-initializers -Wpedantic

mkrefs: mkrefs.cpp
clean:
	rm mkrefs.exe