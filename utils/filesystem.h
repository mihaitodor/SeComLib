/*
SeComLib
Copyright 2012-2013 TU Delft, Information Security & Privacy Lab (http://isplab.tudelft.nl/)

Contributors:
Inald Lagendijk (R.L.Lagendijk@TUDelft.nl)
Mihai Todor (todormihai@gmail.com)
Thijs Veugen (P.J.M.Veugen@tudelft.nl)
Zekeriya Erkin (z.erkin@tudelft.nl)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/**
@file utils/filesystem.h
@brief Definition of class Filesystem.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef FILESYSTEM_HEADER_GUARD
#define FILESYSTEM_HEADER_GUARD

//include C++ headers
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <deque>
#include <algorithm>
#include <stdexcept>

//include boost libraries
#include <boost/filesystem.hpp>

namespace SeComLib {

namespace Utils {

	/**
	@brief Contains utilitary functions for accessing the filesystem

	*/
	class Filesystem {
	public:
		/// Traverses the provided directory (non-recursively) and extracts the absolute paths to all the files in it
		static std::deque<std::string> GetFilesInDirectory(const std::string &directory);

	private:
		/// Default constructor - not implemented
		Filesystem () {}

		/// Destructor - void implementation
		~Filesystem () {}

		/// Copy constructor - not implemented
		Filesystem (Filesystem const &);

		/// Copy assignment operator - not implemented
		Filesystem operator= (Filesystem const &);
	};

}//namespace Utils
}//namespace SeComLib

#endif//FILESYSTEM_HEADER_GUARD