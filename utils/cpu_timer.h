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
@file utils/cpu_timer.h
@brief Definition of class CpuTimer.
@author Mihai Todor (todormihai@gmail.com)
*/

#ifndef CPU_TIMER_HEADER_GUARD
#define CPU_TIMER_HEADER_GUARD

//include boost libraries
//#define BOOST_LIB_DIAGNOSTIC
//let the library have dependencies for now
//#define BOOST_CHRONO_HEADER_ONLY
//#define BOOST_CHRONO_DONT_PROVIDE_HYBRID_ERROR_HANDLING//required in order to avoid dependency on Boost.System
#include "boost/timer/timer.hpp"

//include C++ headers
#include <sstream>

namespace SeComLib {
namespace Utils {
	/**
	@brief Utilitary class providing algorithm timing functionality
	*/
	class CpuTimer {
	public:
		/// Nanosecond data type (int_least64_t)
		typedef boost::timer::nanosecond_type NanosecondType;

		/// Default constructor
		CpuTimer ();

		/// Destructor - void implementation
		~CpuTimer () {}

		/// Stops the timer
		void Stop ();

		/// Resets the timer
		void Reset ();

		/// Returns the elapsed user process time (in nanoseconds)
		NanosecondType GetDuration () const;

		/// Returns the elapsed user process time as a formatted string (HH::MM::SS.mmm)
		std::string ToString () const;

		/// Returns the elapsed user process time as a formatted string (HH::MM::SS.mmm)
		static std::string ToString (CpuTimer::NanosecondType userTime);

	private:
		/// the internal timer variable
		boost::timer::cpu_timer timer;

		/// Copy constructor - not implemented
		CpuTimer (CpuTimer const &);

		/// Copy assignment operator - not implemented
		CpuTimer operator= (CpuTimer const &);
	};

}//namespace Utils
}//namespace SeComLib

#endif//CPU_TIMER_HEADER_GUARD