package com.example.digitalsignature.exception

class InvalidDataException : IllegalArgumentException {
    constructor() : super() {}
    constructor(message: String?) : super(message) {}
}