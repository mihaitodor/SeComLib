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
@file utils/config.h
@brief Definition of class Config.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CONFIG_HEADER_GUARD
#define CONFIG_HEADER_GUARD

//include C++ headers
#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>

//include boost library headers
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>

namespace SeComLib {
namespace Utils {
	/**
	@brief Utilitary class for parsing the configuration file
	
	Works as a singleton: Config::GetInstance().DoStuff()
	*/
	class Config {
	public:
		/// Returns a reference to the singleton
		static Config &GetInstance ();

		/// Template method which returns the value of the specified configuration parameter
		template<typename T>
		T GetParameter (const std::string &parameter) const;

		/// Template method which returns the value of the specified configuration parameter, or defaults to defaultValue
		template<typename T>
		T GetParameter (const std::string &parameter, const T &defaultValue) const;

		/// Sets the location and name of the configuration file
		static void SetConfigFile(const std::string &configFile);

	private:
		/// The internal mapping of the XML configuration file
		boost::property_tree::ptree propertyTree;

		/// The location of the configuration file
		static std::string configFile;

		/// The name of the root node in the configuration XML file
		static const std::string xmlRootElementName;

		/// Default constructor
		/// @todo throw a custom error
		Config ();

		/// Destructor - void implementation
		~Config () {}

		/// Copy constructor - not implemented
		Config (Config const &);

		/// Copy assignment operator - not implemented
		Config operator= (Config const &);
	};

}//namespace Utils
}//namespace SeComLib

//Separate the implementation from the declaration of template methods
#include "config.hpp"

#endif//CONFIG_HEADER_GUARD