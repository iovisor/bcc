/**
 * cbpAnimatedHeader.min.js v1.0.0
 * http://www.codrops.com
 *
 * Licensed under the MIT license.
 * http://www.opensource.org/licenses/mit-license.php
 * 
 * Copyright 2013, Codrops
 * http://www.codrops.com
 */
var cbpAnimatedHeader=(function(){var b=document.documentElement,g=document.querySelector(".cbp-af-header"),e=false,a=300;function f(){window.addEventListener("scroll",function(h){if(!e){e=true;setTimeout(d,250)}},false)}function d(){var h=c();if(h>=a){classie.add(g,"cbp-af-header-shrink")}else{classie.remove(g,"cbp-af-header-shrink")}e=false}function c(){return window.pageYOffset||b.scrollTop}f()})();