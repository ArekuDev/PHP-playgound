
function properlyIndentXML($str,$tabIndent=0){
	// accepts raw XML (as a string) and properly line-breaks and indents it.
	// Presumably would work with HTML tables/etc., too.
	$str = str_replace("<",PHP_EOL."<",$str);
	$str = preg_replace("/>(.+)$/",">".PHP_EOL."$1",$str);

	$re = '/>(.+)$/m';
	$subst = ">".PHP_EOL."$1";
	$str = preg_replace($re, $subst, $str);

	$lines = explode(PHP_EOL,$str);
	foreach($lines as $line){
		if(substr($line,0,2) == "</") {
			$tabIndent--;
			// it's a closing tag, so decrease the indent before outputting the line.
		}
		$ret .= str_repeat("\t",$tabIndent) . $line;
		if(substr($line,0,1) == "<" && substr($line,0,2) != "</" && substr($line,0,2) != "<"."?" && substr($line,-2) != "/>") {
			$tabIndent++;
			//it's an opening tag, so increase the indent after outputting the line.
		} else {
			// line has content and is not an opening or closing tag. Do nothing.
		}
		$ret .= PHP_EOL;
	}

	//delete blank lines
	$ret = preg_replace("/\n\s+\n/","\n",$ret);
	// any node with a single-line value, condense  into a single line like: <tag>value</tag> for readability.
	$re = '/>\n([\s\t]+)?([\w\d\s,.$&*%#@-]+)\n[\s\t]+<\//m';
	$subst = '>$2</';
	$ret = preg_replace($re, $subst, $ret);

	// redact un & pw
	$ret = preg_replace("/<username>(.*)<\/username>/","<username> [ REDACTED ] </username>",$ret);
	$ret = preg_replace("/<password>(.*)<\/password>/","<password> [ REDACTED ] </password>",$ret);
	return($ret);
}
