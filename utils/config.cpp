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
@file utils/config.cpp
@brief Implementation of class Config.
@details Singleton class used to parse the configuration ini file
@author Mihai Todor (todormihai@gmail.com)
*/

#include "config.h"

namespace SeComLib {
namespace Utils {
	/// The default configuration file is located in the same directory as the application (defaults to config.xml)
	std::string Config::configFile ("config.xml");

	/**
	Initialize the name of the XML configuration file root node
	*/
	const std::string Config::xmlRootElementName ("config");

	/**
	Creates a static instance of this class and returns it.
	The instance will be destroyed when the application terminates (singleton pattern).

	@return The static instance of this class
	*/
	Config &Config::GetInstance () {
		static Config instance;
		return instance;
	}

	/**
	@param configFile the location and name of the configuration file
	*/
	void Config::SetConfigFile(const std::string &configFile) {
		Config::configFile = configFile;
	}

	/**
	Parses the configuration file into the boost::property_tree::ptree structure

	If not otherwise specified, it will pick up the file called config.xml in the current directory

	@throws std::runtime_error the provided input file does not exist or can't be read
	*/
	Config::Config () {
		try {
			boost::property_tree::xml_parser::read_xml(Config::configFile, this->propertyTree);
		}
		catch (const boost::property_tree::xml_parser_error &exception) {
			/// @todo throw a custom exception here
			throw std::runtime_error(exception.what());
		}
	}

}//namespace Utils
}//namespace SeComLib