from rest_framework.response import Response


class DeleteMixin:
    def delete(self, request, pk, *args, **kwargs):
        instance = self.queryset.filter(id=pk).last()
        if instance:
            instance.delete()
            serializer = self.serializer_class(instance)
            return Response(serializer.data)
        return Response({'status': False, 'msg': 'Object does not exits'}, status=404)


class RetrieveMixin:

    def retrieve(self, request, pk, *args, **kwargs):
        instance = self.queryset.filter(id=pk).last()
        if instance:
            serializer = self.serializer_class(instance)
            return Response(serializer.data)
        return Response({'status': False, 'msg': 'Object does not exits'}, status=404)


class RetrievedMixin:
    """
    Retrieve a model instance.
    """

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)


class DestroyMixin:
    """
    Destroy a model instance.
    """

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        serializer = self.serializer_class(instance)
        return Response(serializer.data)
