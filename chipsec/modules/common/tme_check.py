# CHIPSEC: Platform Security Assessment Framework
# Copyright (c) 2026, Intel Corporation
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; Version 2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Contact information:
# chipsec@intel.com
#

"""
This module checks that Intel Total Memory Encryption (TME) is enabled and
that the TME configuration is locked by the firmware.

Reference:
    - Intel Architecture Memory Encryption Technologies Specification
    - Intel SDM Volume 4: IA32_TME_CAPABILITY (0x981), IA32_TME_ACTIVATE (0x982)

This module checks the following:
    - IA32_TME_ACTIVATE MSR (0x982) - Bit [0] LOCK and Bit [1] TME_ENABLE on all threads

The module returns the following results:
    - **FAILED** : TME is not enabled or IA32_TME_ACTIVATE is not locked
    - **PASSED** : TME is enabled and IA32_TME_ACTIVATE.LOCK is set on all threads
    - **ERROR**  : Problem reading the TME MSRs

Usage:
  ``chipsec_main -m common.tme_check``

Example:
    >>> chipsec_main.py -m common.tme_check

Registers used:
    - IA32_TME_CAPABILITY
    - IA32_TME_ACTIVATE

.. note::
    - This module only runs when the CPU enumerates TME support
      (CPUID.(EAX=7,ECX=0):ECX[13]).
"""

from typing import List

from chipsec.module_common import BaseModule, HWCONFIG
from chipsec.library.returncode import ModuleResult
from chipsec.library.defines import BIT13
from chipsec.library.exceptions import CSReadError, MSRRegisterError

TAGS = [HWCONFIG]
METADATA_TAGS = ['OPENSOURCE', 'IA', 'COMMON', 'TME']

_MODULE_NAME = 'tme_check'


class tme_check(BaseModule):

    def __init__(self):
        BaseModule.__init__(self)
        self.is_read_error = False
        self.cs.set_scope({
            'IA32_TME_CAPABILITY': '8086.MSR',
            'IA32_TME_ACTIVATE': '8086.MSR',
        })

    def is_supported(self) -> bool:
        if not (self.cs.register.is_defined('IA32_TME_CAPABILITY') and
                self.cs.register.is_defined('IA32_TME_ACTIVATE')):
            self.logger.log_important('TME registers are not defined for the platform.  Skipping module.')
            return False
        if not self.is_tme_supported():
            self.logger.log_important('CPU does not support TME.  Skipping module.')
            return False
        return True

    def is_tme_supported(self) -> bool:
        (_, _, ecx, _) = self.cs.hals.cpu.cpuid(7, 0)
        return ecx & BIT13 != 0

    def log_tme_capability(self) -> None:
        try:
            tme_caps = self.cs.register.get_list_by_name('IA32_TME_CAPABILITY')
            tme_cap = tme_caps[0]
            tme_cap.read()
        except (CSReadError, MSRRegisterError):
            self.logger.log_important('Could not read IA32_TME_CAPABILITY')
            return
        self.logger.log('[*] IA32_TME_CAPABILITY (thread 0):')
        for field in ('AES_XTS_128', 'MK_TME_KEYID_BITS', 'MK_TME_ALG_AES_XTS_128',
                      'MK_TME_ALG_AES_XTS_128_INTEGRITY', 'MK_TME_ALG_AES_XTS_256'):
            if tme_cap.has_field(field):
                self.logger.log(f'  {field}: {tme_cap.get_field(field):d}')

    def check_tme_activate(self) -> bool:
        self.logger.log('[*] Checking IA32_TME_ACTIVATE status on all threads')
        try:
            tme_activate = self.cs.register.get_list_by_name('IA32_TME_ACTIVATE')
            tme_activate.read_and_verbose_print()
        except (CSReadError, MSRRegisterError):
            self.logger.log_important('Could not read IA32_TME_ACTIVATE')
            self.is_read_error = True
            return False
        enabled = tme_activate.is_all_field_value(1, 'TME_ENABLE')
        locked = tme_activate.is_all_field_value(1, 'LOCK')
        if not enabled:
            self.logger.log_bad('TME is not enabled on one or more threads')
        if not locked:
            self.logger.log_bad('IA32_TME_ACTIVATE is not locked on one or more threads')
        return enabled and locked

    def run(self, module_argv: List[str]) -> int:
        self.logger.start_test('Check TME Configuration')
        self.log_tme_capability()
        tme_check_pass = self.check_tme_activate()

        if self.is_read_error:
            self.logger.log_error('There was a problem reading the TME MSRs.')
            self.logger.log_important('Possible the environment or a platform feature is preventing these reads.')
            self.res = ModuleResult.ERROR
            self.result.setStatusBit(self.result.status.ACCESS_RW)
        elif tme_check_pass:
            self.logger.log_passed('TME is enabled and IA32_TME_ACTIVATE.LOCK is set')
            self.res = ModuleResult.PASSED
        else:
            self.logger.log_failed('TME is not enabled and locked')
            self.res = ModuleResult.FAILED
            self.result.setStatusBit(self.result.status.LOCKS)

        return self.result.getReturnCode(self.res)
