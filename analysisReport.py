# ******************************************************************************************************* #
#                                                                                                         #
#  OPENREFACTORY CONFIDENTIAL                                                                             #
#  __________________                                                                                     #
#                                                                                                         #
#  Copyright (c) 2025 OpenRefactory, Inc. All Rights Reserved.                                            #
#                                                                                                         #
#  NOTICE: All information contained herein is, and remains the property of OpenRefactory, Inc. The       #
#  intellectual and technical concepts contained herein are proprietary to OpenRefactory, Inc. and        #
#  may be covered by U.S. and Foreign Patents, patents in process, and are protected by trade secret      #
#  or copyright law. Dissemination of this information or reproduction of this material is strictly       #
#  forbidden unless prior written permission is obtained from OpenRefactory, Inc.                         #
#                                                                                                         #
#  Author: Saadman Ahmed (OpenRefactory, Inc.) - Initial implementation                                   #
# ******************************************************************************************************* #
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List


class AnalysisState(str, Enum):
    """State of vulnerability impact on the component

    Attributes:
        AFFECTED: If the component is affected
        UNAFFECTED: If the component is unaffected
    """

    AFFECTED = "affected"
    UNAFFECTED = "unaffected"


class Justification(str, Enum):
    """Reasoning behind the assesment result

    Attributes:
        FUNCTION_REACHABLE: The function is reachable
        NOT_FUNCTION_REACHABLE: The function is not reachable
    """

    FUNCTION_REACHABLE = "function_reachable"
    NOT_FUNCTION_REACHABLE = "not_function_reachable"


class Response(str, Enum):
    """Intended response to the vulnerability

    Attributes:
        UPDATE: Update to mitigate vulnerability
        WILL_NOT_FIX: Will not fix as vulnerability is not reachable
    """

    UPDATE = "update"
    WILL_NOT_FIX = "will_not_fix"


@dataclass
class ArtifactReachability:
    """The reachability result for a specific package (artifact) in the dependency chain.

    Attributes:
        reachable : Whether the vulnerable method is reachable from this artifact.
        reachable_paths : All method-level paths through which the vulnerability can propagate.
        unreachable_paths : All method-level paths through which the vulnerability can not propagate.
    """

    reachable: bool
    reachable_paths: List[List[Dict[str, Any]]]
    unreachable_paths: List[List[Dict[str, Any]]]


@dataclass
class Explanation:
    """Explanation entry for a reachability or vulnerability verdict. (VEXplanation)

    Attributes:
        verdict : Either "fix" or "will not update"
        message : A detailed explanation with paths.
        author : The identifier ("VGS") that produced the explanation.
        timestamp : The time at which the explanation was generated, typically in ISO 8601 format.
    """

    verdict: str
    message: str
    author: str
    timestamp: str


@dataclass
class AnalysisDetail:
    """Contains detailed results of the vulnerability reachability analysis for a specific component.

    Attributes:
        explanations : A list of explanations describing how the vulnerability
            is reachable, including logical reasoning and supporting evidence.

        root_cause_methods : The list of method signatures identified as the root causes
            of the vulnerability. These are typically the entry points or vulnerable methods
            contributing to exploitability.

        reachability_trace : The reachability trace consisting of all artifacts and paths
            that lead to the vulnerable method, in order of the dependency chain.
    """

    explanations: List[Explanation]
    root_cause_methods: List[str]
    reachability_trace: ArtifactReachability


@dataclass
class AnalysisReport:
    """A high-level summary report of the vulnerability analysis, conforming to VEX schema format.

    Attributes:
        state : Whether the artifact is affected or not.
        justification : Reasoning behind the state decision.
        response : Actions taken or planned in response to the vulnerability.
        detail : Our custom AnalysisDetail object
    """

    detail: AnalysisDetail
    state: AnalysisState = AnalysisState.UNAFFECTED
    justification: Justification = Justification.NOT_FUNCTION_REACHABLE
    response: Response = Response.WILL_NOT_FIX
