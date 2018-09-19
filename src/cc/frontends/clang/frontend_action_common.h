/*
 * Copyright (c) 2018 Facebook, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#if LLVM_MAJOR_VERSION >= 8
#define GET_BEGINLOC(E)  ((E)->getBeginLoc())
#define GET_ENDLOC(E)  ((E)->getEndLoc())
#else
#define GET_BEGINLOC(E)  ((E)->getLocStart())
#define GET_ENDLOC(E)    ((E)->getLocEnd())
#endif
