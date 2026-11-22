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

# To execute: python[3] -m unittest tests.modules.test_tme_check

import unittest
import os
from types import SimpleNamespace
from unittest.mock import Mock

from chipsec.testcase import ExitCode
from chipsec.library.exceptions import MSRRegisterError
from chipsec.library.file import get_main_dir
from chipsec.library.returncode import ModuleResult
from chipsec.modules.common.tme_check import tme_check
from tests.modules.run_chipsec_module import setup_run_destroy_module


class TestTmeCheck(unittest.TestCase):
    def setUp(self) -> None:
        self.init_replay_file = os.path.join(get_main_dir(), "tests", "utilcmd", "adlenumerate2.json")
        self.folder_path = os.path.join(get_main_dir(), "tests", "modules")

    def run_tme_check(self, replay_file: str) -> int:
        module_replay_file = os.path.join(self.folder_path, replay_file)
        return setup_run_destroy_module(self.init_replay_file, "common.tme_check",
                                        module_replay_file=module_replay_file)

    def test_tme_check_pass(self) -> None:
        retval = self.run_tme_check("tme_check_pass.json")
        self.assertEqual(retval, ExitCode.OK)

    def test_tme_check_unlocked(self) -> None:
        retval = self.run_tme_check("tme_check_unlocked.json")
        self.assertEqual(retval, ExitCode.FAIL)

    def test_tme_check_disabled(self) -> None:
        retval = self.run_tme_check("tme_check_disabled.json")
        self.assertEqual(retval, ExitCode.FAIL)

    def test_tme_check_unsupported(self) -> None:
        retval = self.run_tme_check("tme_check_unsupported.json")
        self.assertEqual(retval, ExitCode.NOTAPPLICABLE)

    def test_tme_check_read_error(self) -> None:
        module = tme_check.__new__(tme_check)
        module.res = ModuleResult.PASSED
        module.is_read_error = False
        module.logger = Mock()
        module.result = Mock()
        module.result.status = SimpleNamespace(ACCESS_RW=object(), LOCKS=object())
        module.result.getReturnCode.side_effect = lambda value, print_output=True: value
        module.cs = SimpleNamespace(register=Mock())
        module.cs.register.get_list_by_name.side_effect = MSRRegisterError('read failed')

        result = module.run([])

        self.assertEqual(ModuleResult.ERROR, result)
        module.result.setStatusBit.assert_called_once_with(module.result.status.ACCESS_RW)
        module.logger.log_error.assert_called_once()


if __name__ == '__main__':
    unittest.main()
