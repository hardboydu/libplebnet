;;; gtags.el --- gtags facility for Emacs

;;
;; Copyright (c) 1997, 1998, 1999 Shigio Yamaguchi. All rights reserved.
;;
;; Redistribution and use in source and binary forms, with or without
;; modification, are permitted provided that the following conditions
;; are met:
;; 1. Redistributions of source code must retain the above copyright
;;    notice, this list of conditions and the following disclaimer.
;; 2. Redistributions in binary form must reproduce the above copyright
;;    notice, this list of conditions and the following disclaimer in the
;;    documentation and/or other materials provided with the distribution.
;; 3. All advertising materials mentioning features or use of this software
;;    must display the following acknowledgement:
;;       This product includes software developed by Shigio Yamaguchi.
;; 4. Neither the name of the author nor the names of any co-contributors
;;    may be used to endorse or promote products derived from this software
;;    without specific prior written permission.
;;
;; THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
;; ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
;; IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
;; ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
;; FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
;; DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
;; OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
;; HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
;; LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
;; OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
;; SUCH DAMAGE.
;;
;;	gtags.el	8-Jan-99
;;

;; This file is part of GLOBAL.
;; Author: Shigio Yamaguchi <shigio@wafu.netgate.net>
;; Version: 1.5
;; Keywords: tools

;;; Code

(defvar gtags-buffer-stack nil
  "Stack for tag browsing.")
(defvar gtags-point-stack nil
  "Stack for tag browsing.")
(defvar gtags-complete-list nil
  "Gtags complete list.")
(defconst symbol-regexp "[A-Za-z_][A-Za-z_0-9]*"
  "Regexp matching tag name.")
(defconst definition-regexp "#[ \t]*define[ \t]+\\|ENTRY(\\|ALTENTRY("
  "Regexp matching tag definition name.")
(defvar gtags-read-only nil
  "Gtags read only mode")
(defvar gtags-mode-map (make-sparse-keymap)
  "Keymap used in gtags mode.")
(define-key gtags-mode-map "\et" 'gtags-find-tag)
(define-key gtags-mode-map "\er" 'gtags-find-rtag)
(define-key gtags-mode-map "\es" 'gtags-find-symbol)
(define-key gtags-mode-map "\eg" 'gtags-find-pattern)
(define-key gtags-mode-map "\C-]" 'gtags-find-tag-from-here)
(define-key gtags-mode-map "\eh" 'gtags-display-browser)
(define-key gtags-mode-map "\C-t" 'gtags-pop-stack)
(define-key gtags-mode-map "\e." 'etags-style-find-tag)
(define-key gtags-mode-map [mouse-2] 'gtags-find-tag-by-event)
(define-key gtags-mode-map [mouse-3] 'gtags-pop-stack)

(defvar gtags-select-mode-map (make-sparse-keymap)
  "Keymap used in gtags select mode.")
(define-key gtags-select-mode-map "q" 'gtags-pop-stack)
(define-key gtags-select-mode-map "\C-t" 'gtags-pop-stack)
(define-key gtags-select-mode-map "\C-m" 'gtags-select-tag)
(define-key gtags-select-mode-map " " 'scroll-up)
(define-key gtags-select-mode-map "\^?" 'scroll-down)
(define-key gtags-select-mode-map "\C-f" 'scroll-up)
(define-key gtags-select-mode-map "\C-b" 'scroll-down)
(define-key gtags-select-mode-map "n" 'next-line)
(define-key gtags-select-mode-map "p" 'previous-line)
(define-key gtags-select-mode-map "j" 'next-line)
(define-key gtags-select-mode-map "k" 'previous-line)
(define-key gtags-select-mode-map [mouse-2] 'gtags-select-tag-by-event)
(define-key gtags-select-mode-map [mouse-3] 'gtags-pop-stack)

;;
;; utility
;;
(defun util-match-string (n)
  (buffer-substring (match-beginning n) (match-end n)))

;; Return a default tag to search for, based on the text at point.
(defun gtags-current-token ()
  (cond
   ((looking-at "[0-9A-Za-z_]")
    (while (looking-at "[0-9A-Za-z_]")
      (forward-char -1))
    (forward-char 1))
   (t
    (while (looking-at "[ \t]")
      (forward-char 1))))
  (if (and (bolp) (looking-at definition-regexp))
      (goto-char (match-end 0)))
  (if (looking-at symbol-regexp)
      (util-match-string 0) nil))

;; push current context to stack
(defun push-context ()
  (setq gtags-buffer-stack (cons (current-buffer) gtags-buffer-stack))
  (setq gtags-point-stack (cons (point) gtags-point-stack)))

;; pop context from stack
(defun pop-context ()
  (if (not gtags-buffer-stack) nil
    (let (buffer point)
      (setq buffer (car gtags-buffer-stack))
      (setq gtags-buffer-stack (cdr gtags-buffer-stack))
      (setq point (car gtags-point-stack))
      (setq gtags-point-stack (cdr gtags-point-stack))
      (list buffer point))))

;; if the buffer exist in the stack
(defun exist-in-stack (buffer)
  (memq buffer gtags-buffer-stack))

;; is it a function?
(defun is-function ()
  (save-excursion
    (while (and (not (eolp)) (looking-at "[0-9A-Za-z_]"))
      (forward-char 1))
    (while (and (not (eolp)) (looking-at "[ \t]"))
      (forward-char 1))
    (if (looking-at "(") t nil)))

;; is it a definition?
(defun is-definition ()
  (save-excursion
    (if (and (string-match "\.java$" buffer-file-name) (looking-at "[^(]+([^)]*)[ \t]*{"))
	t
      (if (bolp)
	  t
        (forward-word -1)
        (cond
         ((looking-at "define")
	  (forward-char -1)
	  (while (and (not (bolp)) (looking-at "[ \t]"))
	    (forward-char -1))
	  (if (and (bolp) (looking-at "#"))
	      t nil))
         ((looking-at "ENTRY\\|ALTENTRY")
	  (if (bolp) t nil)))))))

;;
;; interactive command
;;
(defun gtags-find-tag ()
  "Input tag name and move to the definition."
  (interactive)
  (let (tagname)
    (setq tagname (completing-read ":tag " gtags-complete-list))
    (push-context)
    (gtags-goto-tag tagname "")))

(defun etags-style-find-tag ()
  "Input tag name and move to the definition.(etags style)"
  (interactive)
  (let (tagname prompt input)
    (setq tagname (gtags-current-token))
    (if tagname
        (setq prompt (concat "Find tag: (default " tagname ") "))
      (setq prompt "Find tag: "))
    (setq input (completing-read prompt gtags-complete-list))
    (if (not (equal "" input)) (setq tagname input))
    (push-context)
    (gtags-goto-tag tagname "")))

(defun gtags-find-symbol ()
  "Input symbol and move to the locations."
  (interactive)
  (let (tagname prompt input)
    (setq tagname (gtags-current-token))
    (if tagname
        (setq prompt (concat "Find symbol: (default " tagname ") "))
      (setq prompt "Find symbol: "))
    (setq input (read-string prompt))
    (if (not (equal "" input)) (setq tagname input))
    (push-context)
    (gtags-goto-tag tagname "s")))

(defun gtags-find-pattern ()
  "Input pattern and move to the locations."
  (interactive)
  (let (tagname prompt input)
    (setq tagname (gtags-current-token))
    (if tagname
        (setq prompt (concat "Find pattern: (default " tagname ") "))
      (setq prompt "Find pattern: "))
    (setq input (read-string prompt))
    (if (not (equal "" input)) (setq tagname input))
    (push-context)
    (gtags-goto-tag tagname "g")))

(defun gtags-find-rtag ()
  "Input tag name and move to the referenced point."
  (interactive)
  (let (tagname)
    (setq tagname (completing-read ":rtag " gtags-complete-list))
    (push-context)
    (gtags-goto-tag tagname "r")))

(defun gtags-find-tag-from-here ()
  "Get the expression as a tagname around here and move there."
  (interactive)
  (let (tagname flag)
    (setq tagname (gtags-current-token))
    (if (is-function)
        (if (is-definition) (setq flag "r") (setq flag ""))
      (setq flag "s"))
    (if (not tagname)
        nil
      (push-context)
      (gtags-goto-tag tagname flag))))

(defun gtags-display-browser ()
  "Display current screen on hypertext browser."
  (interactive)
  (let (lno)
    (save-excursion
      (end-of-line)
      (if (equal (point-min) (point))
          (setq lno 1)
        (setq lno (count-lines (point-min) (point)))))
    (message (number-to-string lno))
    (call-process "gozilla"  nil t nil (concat "+" (number-to-string lno)) buffer-file-name)))

(defun gtags-find-tag-by-event (event)
  "Get the expression as a tagname around here and move there."
  (interactive "e")
  (select-window (posn-window (event-end event)))
  (set-buffer (window-buffer (posn-window (event-end event))))
  (goto-char (posn-point (event-end event)))
  (let (tagname flag)
    (if (= 0 (count-lines (point-min) (point-max)))
        (progn (setq tagname "main") (setq flag ""))
      (setq tagname (gtags-current-token))
      (if (is-function)
          (if (is-definition) (setq flag "r") (setq flag ""))
        (setq flag "s")))
    (if (not tagname)
        nil
      (push-context)
      (gtags-goto-tag tagname flag))))

(defun gtags-select-tag ()
  "Select a tagname in [GTAGS SELECT MODE] and move there."
  (interactive)
  (push-context)
  (gtags-select-it nil))

(defun gtags-select-tag-by-event (event)
  "Select a tagname in [GTAGS SELECT MODE] and move there."
  (interactive "e")
  (select-window (posn-window (event-end event)))
  (set-buffer (window-buffer (posn-window (event-end event))))
  (goto-char (posn-point (event-end event)))
  (push-context)
  (gtags-select-it nil))

(defun gtags-pop-stack ()
  "Move to previous point on the stack."
  (interactive)
  (let (delete context buffer)
    (if (not (exist-in-stack (current-buffer)))
	(setq delete t))
    (setq context (pop-context))
    (if (not context)
	(message "The tags stack is empty.")
      (if delete
	  (kill-buffer (current-buffer)))
      (switch-to-buffer (nth 0 context))
      (goto-char (nth 1 context)))))

;;
;; common function
;;

;; goto tag's point
(defun gtags-goto-tag (tagname flag)
  (let (save prefix buffer lines)
    (setq save (current-buffer))
    (cond
     ((equal flag "g")
      (setq prefix "(G)"))
     ((equal flag "s")
      (setq prefix "(S)"))
     ((equal flag "r")
      (setq prefix "(R)"))
     (t (setq prefix "(D)")))
    ;; load tag
    (setq buffer (generate-new-buffer (generate-new-buffer-name (concat prefix tagname))))
    (set-buffer buffer)
    (if (not (= 0 (call-process "global" nil t nil (concat "-ax" flag) tagname)))
	(progn (message (buffer-substring (point-min)(1- (point-max))))
               (pop-context))
      (goto-char (point-min))
      (setq lines (count-lines (point-min) (point-max)))
      (cond
       ((= 0 lines)
	(message "%s: tag not found" tagname)
	(pop-context)
	(kill-buffer buffer)
	(set-buffer save))
       ((= 1 lines)
	(gtags-select-it t))
       (t
	(switch-to-buffer buffer)
	(gtags-select-mode))))))

;; select a tag line from lines
(defun gtags-select-it (delete)
  (let (line file)
    ;; get context from current tag line
    (beginning-of-line)
;;    (if (not (looking-at "[A-Za-z_][A-Za-z_0-9]*[ \t]+\\([0-9]+\\)[ \t]\\([^ \t]+\\)[ \t]"))
    (if (not (looking-at "[^ \t]+[ \t]+\\([0-9]+\\)[ \t]\\([^ \t]+\\)[ \t]"))
        (pop-context)
      (setq line (string-to-number (util-match-string 1)))
      (setq file (util-match-string 2))
      (if delete (kill-buffer (current-buffer)))
      ;; move to the context
      (if gtags-read-only (find-file-read-only file) (find-file file))
      (goto-line line)
      (use-local-map gtags-mode-map))))

;; make complete list
(defun make-gtags-complete-list ()
;;  "Make tag name list for completion."
;;  (interactive)
  (save-excursion
    (setq gtags-complete-list (make-vector 63 0))
    (set-buffer (generate-new-buffer "*Completions*"))
    (call-process "global" nil t nil "-c")
    (goto-char (point-min))
    (while (looking-at symbol-regexp)
      (intern (util-match-string 0) gtags-complete-list)
      (forward-line))
    (kill-buffer (current-buffer))))

;;;###autoload
(defun gtags-mode ()
  "Minor mode for browsing C source using GLOBAL."
  (interactive)
  (if (y-or-n-p "Do you use function name completion?")
    (make-gtags-complete-list))
  (use-local-map gtags-mode-map)
  (run-hooks 'gtags-mode-hook))

;; make gtags select mode
(defun gtags-select-mode ()
  "Major mode for choosing a tag from tags list."
  (setq buffer-read-only t
        major-mode 'gtags-select-mode
        mode-name "Gtags Select")
  (use-local-map gtags-select-mode-map)
  (setq truncate-lines t)
  (goto-char (point-min))
  (message "[GTAGS SELECT MODE] %d lines" (count-lines (point-min) (point-max)))
  (run-hooks 'gtags-select-mode-hook))

;;; gtags.el ends here
