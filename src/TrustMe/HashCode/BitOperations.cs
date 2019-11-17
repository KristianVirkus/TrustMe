// Adapted on 20 Jun 2019 from
// https://github.com/dotnet/corefx/blob/master/src/Microsoft.Bcl.HashCode/src/BitOperations.cs

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See license information below for more details:

/*
The MIT License(MIT)

Copyright(c) .NET Foundation and Contributors

All rights reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

using System.Runtime.CompilerServices;

namespace HashCode
{
	// NOTE: This class is a copy from src\Common\src\CoreLib\System\Numerics\BitOperations.cs only for HashCode purposes.
	// Any changes to the BitOperations class should be done in there instead.
	internal static class BitOperations
	{
		/// <summary>
		/// Rotates the specified value left by the specified number of bits.
		/// Similar in behavior to the x86 instruction ROL.
		/// </summary>
		/// <param name="value">The value to rotate.</param>
		/// <param name="offset">The number of bits to rotate by.
		/// Any value outside the range [0..31] is treated as congruent mod 32.</param>
		/// <returns>The rotated value.</returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint RotateLeft(uint value, int offset)
			=> (value << offset) | (value >> (32 - offset));

		/// <summary>
		/// Rotates the specified value left by the specified number of bits.
		/// Similar in behavior to the x86 instruction ROL.
		/// </summary>
		/// <param name="value">The value to rotate.</param>
		/// <param name="offset">The number of bits to rotate by.
		/// Any value outside the range [0..63] is treated as congruent mod 64.</param>
		/// <returns>The rotated value.</returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static ulong RotateLeft(ulong value, int offset)
			=> (value << offset) | (value >> (64 - offset));
	}
}
