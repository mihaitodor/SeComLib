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
@file utils/filesystem.cpp
@brief Implementation of class Filesystem.
@details Utilitary class for accessing the filesystem
@author Mihai Todor (todormihai@gmail.com)
*/

#include "filesystem.h"

namespace SeComLib {
namespace Utils {
	/**
	Doesn't support non-ASCII file names

	@param directory the absolute path to the directory
	@return a vector of file names (including extension)
	*/
	std::deque<std::string> Filesystem::GetFilesInDirectory(const std::string &directory) {
		std::deque<std::string> output;

		if (boost::filesystem::is_directory(directory)) {
			for (boost::filesystem::directory_iterator iterator(directory); iterator != boost::filesystem::directory_iterator(); ++iterator) {
				if (boost::filesystem::is_regular_file(*iterator)) {
					output.emplace_back(iterator->path().filename().string());
				}
			}
		}

		return output;
	}
}//namespace Utils
}//namespace SeComLib