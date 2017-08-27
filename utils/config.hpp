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
@file utils/config.hpp
@brief Implementation of template members from class Config.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CONFIG_IMPLEMENTATION_GUARD
#define CONFIG_IMPLEMENTATION_GUARD

namespace SeComLib {
namespace Utils {
	/**
	Example: GetParameter<int>("key1.key2.key3");

	@param parameter a string wich contains the keys required to locate the required value in the XML tree.
	@return the queried value
	*/
	template<typename T>
	T Config::GetParameter (const std::string &parameter) const {
		return this->propertyTree.get<T>(Config::xmlRootElementName + "." + parameter);
	}

	/**
	Deduces the template type from the defaultValue parameter.

	Example: GetParameter("key1.key2.key3", 0U);//the returned value will have type unsigned int

	@param parameter a string wich contains the keys required to locate the required value in the XML tree.
	@param defaultValue the method will return this value if the configuration file does not contain the queried data
	@return the queried value
	*/
	template<typename T>
	T Config::GetParameter (const std::string &parameter, const T &defaultValue) const {
		return this->propertyTree.get(Config::xmlRootElementName + "." + parameter, defaultValue);
	}

}//namespace Utils
}//namespace SeComLib

#endif//CONFIG_IMPLEMENTATION_GUARD