/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/*jslint devel: true, node: true, nomen: true, stupid: true */
'use strict';



// Variables
const _ = require('lodash'),
    strategy = require('./strategy');


// Export module
module.exports = function (type, options) {
    if (_.isObject(type)) {
        options = type;
        type = options.type;
    }

    return strategy[type](options);
};



/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * c-hanging-comment-ender-p: nil
 * End:
 */
