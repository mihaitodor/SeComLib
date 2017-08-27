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
@file utils/cpu_timer.cpp
@brief Implementation of class CpuTimer.
@details Provides a basic timer for measuring the elapsed CPU time.
@author Mihai Todor (todormihai@gmail.com)
*/

#include "cpu_timer.h"

namespace SeComLib {
namespace Utils {
	/**
	Initialize and start the timer
	*/
	CpuTimer::CpuTimer () {
		this->timer.start();
	}

	/**
	*/
	void CpuTimer::Stop () {
		this->timer.stop();
	}

	/**
	*/
	void CpuTimer::Reset () {
		this->timer = boost::timer::cpu_timer();
	}

	/**
	@return The elapsed user process time (in nanoseconds)
	*/
	CpuTimer::NanosecondType CpuTimer::GetDuration () const {
		return this->timer.elapsed().user;
	}

	/**
	@return Formatted string of the elapsed user process time (HH::MM::SS.mmm)
	*/
	std::string CpuTimer::ToString () const {
		return CpuTimer::ToString(this->GetDuration());
	}

	/**
	@param userTime a time duration expressed in nanoseconds
	@return a string containing the formatted user time 
	*/
	std::string CpuTimer::ToString (CpuTimer::NanosecondType userTime) {
		std::stringstream output;

		int_least64_t userTimeMilliseconds = static_cast<int_least64_t>(userTime / 1000000);

		int_least64_t miliseconds = userTimeMilliseconds % 1000;
		int_least64_t seconds = userTimeMilliseconds / 1000;
		int_least64_t hours = seconds / 3600;
		seconds = seconds % 3600;
		int_least64_t minutes = seconds / 60;
		seconds = seconds % 60;

		/// Format the output string
		if (hours < 10) output << "0" << hours;
		else output << hours;
		output << ":";
		if (minutes < 10) output << "0" << minutes;
		else output << minutes;
		output << ":";
		if (seconds < 10) output << "0" << seconds;
		else output << seconds;
		output << ".";
		if (miliseconds < 10) output << "00" << miliseconds;
		else if (miliseconds < 100) output << "0" << miliseconds;
		else output << miliseconds;

		return output.str();
	}

}//namespace Utils
}//namespace SeComLib