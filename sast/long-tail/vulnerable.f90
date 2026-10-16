! File:    vulnerable.f90
! Purpose: SAST fixture (Fortran). Shell execution and tainted file open.
! Author:  Vigilnz Security Engineering
! Date:    2026-10-16
! Expected rules: fortran-execute-command, fortran-open

program vulnerable
    implicit none
    character(len=256) :: user_input
    integer :: exit_status

    call get_command_argument(1, user_input)

    ! CWE-78: command built from an untrusted argument
    call execute_command_line("ping -c 1 " // trim(user_input), exitstat=exit_status)

    ! CWE-22: path traversal
    OPEN(FILE="/srv/files/" // trim(user_input), UNIT=10, STATUS="OLD")
    CLOSE(10)
end program vulnerable
