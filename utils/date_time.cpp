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
@file utils/date_time.cpp
@brief Implementation of class DateTime.
@details Provides date and time specific utilitary functions.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "date_time.h"

namespace SeComLib {
namespace Utils {
	/**
	@param format the format of the output string (defaults to "%H:%M:%S")
	@return a string representation of the current time
	*/
	std::string DateTime::Now (const std::string &format) {
		/// Get current time
		std::time_t now = std::time(0);

		//allocate a C-style buffer
		char charArray[128];

		std::strftime(charArray, sizeof(charArray), format.c_str(), localtime(&now)) ;

		return std::string(charArray);
	}

}//namespace Utils
}//namespace SeComLib