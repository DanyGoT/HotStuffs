;;; Directory Local Variables            -*- no-byte-compile: t -*-

((org-mode
  . ((eval . (add-to-list
              'org-latex-classes
              '("uis-thesis"
                "\\documentclass[11pt,oneside]{book}"
                ("\\chapter{%s}" . "\\chapter*{%s}")
                ("\\section{%s}" . "\\section*{%s}")
                ("\\subsection{%s}" . "\\subsection*{%s}")
                ("\\subsubsection{%s}" . "\\subsubsection*{%s}")
                ("\\paragraph{%s}" . "\\paragraph*{%s}")))))))
