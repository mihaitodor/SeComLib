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
@file utils/date_time.h
@brief Definition of class DateTime.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef DATE_TIME_HEADER_GUARD
#define DATE_TIME_HEADER_GUARD

//defined for WIN64 as well
#ifdef _WIN32
	/// Get rid of nagging errors about localtime(...)
	#define _CRT_SECURE_NO_WARNINGS
#endif

//include C++ headers
#include <ctime>
#include <string>

namespace SeComLib {
namespace Utils {
	/**
	@brief Utilitary class providing date and time functions
	*/
	class DateTime {
	public:
		/// Returns the formatted current time
		static std::string Now (const std::string &format = "%H:%M:%S");

	private:
		/// Default constructor - not implemented
		DateTime ();

		/// Destructor - void implementation
		~DateTime ();

		/// Copy constructor - not implemented
		DateTime (DateTime const &);

		/// Copy assignment operator - not implemented
		DateTime operator= (DateTime const &);
	};

}//namespace Utils
}//namespace SeComLib

#endif//DATE_TIME_HEADER_GUARD