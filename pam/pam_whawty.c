//
// Copyright (c) 2016 Christian Pointner <equinox@spreadspace.org>
//               2016 Markus Grüneis <gimpf@gimpf.org>
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// * Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// * Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// * Neither the name of whawty.auth nor the names of its
//   contributors may be used to endorse or promote products derived from
//   this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
//
// This is based on simple-pam by T. Jameson Little licensed under MIT License.
// The source code of simple-pam can be found at:
//   https://github.com/beatgammit/simple-pam
// The complete license text can be found in the file LICENSE.simple-pam.
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PAM_SM_AUTH

#include <security/pam_modules.h>

#define UNUSED(x) (void)(x)

// Authentication management

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  UNUSED(flags);
  UNUSED(argc);
  UNUSED(argv);

  int retval;
  const char* pUsername;
  retval = pam_get_user(pamh, &pUsername, NULL);
  if (retval != PAM_SUCCESS) {
    return retval;
  }

  printf("whawty welcomes %s\n", pUsername);

  if (strcmp(pUsername, "equinox") != 0) {
    return PAM_AUTH_ERR;
  }

  return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
  UNUSED(pamh);
  UNUSED(flags);
  UNUSED(argc);
  UNUSED(argv);
  return PAM_CRED_ERR;
}

/* static module data */
#ifdef PAM_STATIC

struct pam_module _pam_whawty_modstruct = {
    "pam_whawty",
    pam_sm_authenticate,
    pam_sm_setcred,
    NULL,
    NULL,
    NULL,
    NULL
};

#endif
