<!-- $FreeBSD$ -->
<!-- Origianl revision: 1.2 -->

<!DOCTYPE style-sheet PUBLIC "-//James Clark//DTD DSSSL Style Sheet//EN" [
<!ENTITY release.dsl PUBLIC "-//FreeBSD//DOCUMENT Release Notes DocBook Language Neutral Stylesheet//EN" CDATA DSSSL>
<!ENTITY % output.html  "IGNORE"> 
<!ENTITY % output.print "IGNORE">
]>

<style-sheet>
  <style-specification use="docbook">
    <style-specification-body>
 
      <![ %output.html; [ 
	(define ($email-footer$)
          (make sequence
	    (make element gi: "p"
                  attributes: (list (list "align" "center"))
              (make element gi: "small"
                (literal "���Υե������¾, ��꡼����Ϣ��ʸ��� ")
		(create-link (list (list "HREF" (entity-text "release.url")))
                  (literal (entity-text "release.url")))
                (literal " �����������ɤǤ��ޤ�.")))
            (make element gi: "p"
                  attributes: (list (list "align" "center"))
              (make element gi: "small"  
                (literal "FreeBSD �˴ؤ��뤪�䤤��碌��, <")
		(create-link
                  (list (list "HREF" "mailto:questions@FreeBSD.org"))
                  (literal "questions@FreeBSD.org"))
                (literal "> �ؼ������Ƥ�������")
		(create-link
		  (list (list "HREF" "http://www.FreeBSD.org/docs.html"))
                  (literal "����ʸ��"))
                (literal "���ɤߤ�������.")
            (make element gi: "p"
                  attributes: (list (list "align" "center"))
              (make element gi: "small"  
                (literal "FreeBSD ")
		(literal (entity-text "release.branch"))
		(literal " �򤪻Ȥ�������, ���� ")
                (literal "<")
		(create-link (list (list "HREF" "mailto:current@FreeBSD.org"))
                  (literal "current@FreeBSD.org"))
                (literal "> �᡼��󥰥ꥹ�Ȥ˻��ä�������.")))

            (make element gi: "p"
                  attributes: (list (list "align" "center"))
	      (literal "����ʸ��θ�ʸ�˴ؤ��뤪�䤤��碌�� <")
	      (create-link (list (list "HREF" "mailto:doc@FreeBSD.org"))
                (literal "doc@FreeBSD.org"))
	      (literal "> �ޤ�, ")
              (make empty-element gi: "br")
	      (literal "���ܸ��Ǥ˴ؤ��뤪�䤤��碌��, <")
	      (create-link (list (list "HREF" "mailto:doc-jp@jp.FreeBSD.org"))
                 (literal "doc-jp@jp.FreeBSD.org"))
	      (literal "> �ޤ��Żҥ᡼��Ǥ��ꤤ���ޤ�."))))))


	<!-- Convert " ... " to `` ... '' in the HTML output. -->
	(element quote
	  (make sequence
	    (literal "``")
	    (process-children)
	    (literal "''")))

        <!-- Generate links to HTML man pages -->
        (define %refentry-xref-link% #t)

        <!-- Specify how to generate the man page link HREF -->
        (define ($create-refentry-xref-link$ refentrytitle manvolnum)
	  (string-append "http://www.FreeBSD.org/cgi/man.cgi?query="
			 refentrytitle "&" "sektion=" manvolnum))
      ]]>
    </style-specification-body>
  </style-specification>

  <external-specification id="docbook" document="release.dsl">
</style-sheet>
